// SPDX-License-Identifier: GPL-2.0
// Module: datagrams. UDP, ICMP (ping sockets), raw and SCTP sockets sending
// (one kernel function per socket type, one shared body) and receiving
// (two kernel functions, one shared body).
#ifndef CONN_MON_DATAGRAM_BPF_H
#define CONN_MON_DATAGRAM_BPF_H

#include "common.bpf.h"

// datagram_send reports a datagram a process is sending. The destination is
// in the message when the program used sendto() or sendmsg() with an address
// (the kernel has already copied that address into its own memory by now);
// otherwise the socket is connected and the destination is in the socket.
static __always_inline int datagram_send(struct sock *sk, struct msghdr *msg)
{
	struct event e;
	__builtin_memset(&e, 0, sizeof(e));

	e.kind = KIND_OUT;

	fill_process(&e);
	fill_socket(&e, sk);
	remember_owner(sk, &e);

	const void *name = BPF_CORE_READ(msg, msg_name);
	const int namelen = BPF_CORE_READ(msg, msg_namelen);
	__u16 fam = 0;

	if (name && namelen >= 2)
		bpf_probe_read_kernel(&fam, sizeof(fam), name); // sa_family comes first

	if (fam == AF_INET && namelen >= (int)sizeof(struct sockaddr_in)) {
		struct sockaddr_in sin;
		bpf_probe_read_kernel(&sin, sizeof(sin), name);

		e.family = AF_INET; // an IPv6 socket may send to an IPv4 address

		fill_local(&e, sk); // so re-read the local side in that family

		e.dport = bpf_ntohs(sin.sin_port);

		__builtin_memset(e.daddr, 0, sizeof(e.daddr));
		__builtin_memcpy(e.daddr, &sin.sin_addr, 4);
	} else if (fam == AF_INET6 && namelen >= (int)sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 sin6;
		bpf_probe_read_kernel(&sin6, sizeof(sin6), name);

		e.family = AF_INET6;

		fill_local(&e, sk);

		e.dport = bpf_ntohs(sin6.sin6_port);

		__builtin_memcpy(e.daddr, &sin6.sin6_addr, 16);
	}

	if (e.socktype == SOCK_RAW)
		e.sport = e.dport = 0;

	if (seen_recently(&e))
		return 0;

	emit(&e);

	return 0;
}

// The send function of each datagram socket type. They all take (socket,
// message, length), so one body serves them all.
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(handle_udp_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return datagram_send(sk, msg);
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(handle_udpv6_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return datagram_send(sk, msg);
}

SEC("kprobe/ping_v4_sendmsg")
int BPF_KPROBE(handle_ping_v4_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return datagram_send(sk, msg);
}

SEC("kprobe/ping_v6_sendmsg")
int BPF_KPROBE(handle_ping_v6_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return datagram_send(sk, msg);
}

SEC("kprobe/raw_sendmsg")
int BPF_KPROBE(handle_raw_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return datagram_send(sk, msg);
}

SEC("kprobe/rawv6_sendmsg")
int BPF_KPROBE(handle_rawv6_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return datagram_send(sk, msg);
}

SEC("kprobe/sctp_sendmsg")
int BPF_KPROBE(handle_sctp_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return datagram_send(sk, msg);
}

// datagram_recv reports a datagram a process has just read. We are inside
// that process's recvmsg() call, and the packet headers are still there.
static __always_inline int datagram_recv(struct sock *sk, struct sk_buff *skb)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0; // unix, netlink and packet sockets use skb_free_datagram too

	struct event e;
	__builtin_memset(&e, 0, sizeof(e));

	e.kind = KIND_IN;

	fill_process(&e);

	e.socktype = BPF_CORE_READ(sk, sk_type);
	if (parse_headers(&e, skb, 1) < 0)
		return 0;

	remember_owner(sk, &e);

	if (seen_recently(&e))
		return 0;

	emit(&e);

	return 0;
}

// A process read a UDP datagram.
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(handle_skb_consume_udp, struct sock *sk, struct sk_buff *skb)
{
	return datagram_recv(sk, skb);
}

// A process read a datagram from a ping, raw or other socket.
SEC("kprobe/skb_free_datagram")
int BPF_KPROBE(handle_skb_free_datagram, struct sock *sk, struct sk_buff *skb)
{
	return datagram_recv(sk, skb);
}

#endif // CONN_MON_DATAGRAM_BPF_H
