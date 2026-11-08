// SPDX-License-Identifier: GPL-2.0
// Module: packet sockets, the kind that works below IP. Opening or binding
// one (sniffers, ARP, DHCP clients) and sending frames through one.
#ifndef CONN_MON_PACKET_BPF_H
#define CONN_MON_PACKET_BPF_H

#include "common.bpf.h"

#define AF_PACKET 17

// ll_addr is struct sockaddr_ll, the address of a packet socket
// (linux/if_packet.h), spelled out so we don't depend on vmlinux.h for it.
struct ll_addr {
	__u16 family;    // AF_PACKET
	__be16 protocol; // ethertype, network byte order
	__s32 ifindex;
	__u16 hatype;
	__u8 pkttype;
	__u8 halen;      // how many bytes of addr are used
	__u8 addr[8];    // the hardware address
};

// fill_packet_socket records the interface and ethertype a packet socket is
// bound to. The kernel keeps them in packet_sock, which wraps the generic
// socket as its first member, so the pointer can simply be cast.
static __always_inline void fill_packet_socket(struct event *e, struct socket *sock)
{
	struct sock *sk = BPF_CORE_READ(sock, sk);
	struct packet_sock *po = (struct packet_sock *)sk;

	e->family = AF_PACKET;
	e->socktype = BPF_CORE_READ(sk, sk_type);
	e->ifindex = BPF_CORE_READ(po, ifindex);
	e->ethertype = bpf_ntohs(BPF_CORE_READ(po, num));
}

// A packet socket is created with a protocol, which makes it receive on all
// interfaces at once. Sockets created with protocol 0 do nothing until
// bound; handle_packet_bind reports those.
SEC("kprobe/packet_create")
int BPF_KPROBE(handle_packet_create, struct net *net, struct socket *sock, int protocol)
{
	if (!protocol)
		return 0;

	struct event e;
	__builtin_memset(&e, 0, sizeof(e));

	e.kind = KIND_CAPTURE;

	fill_process(&e);

	e.family = AF_PACKET;
	e.socktype = BPF_CORE_READ(sock, type);
	e.ethertype = bpf_ntohs((__be16)protocol);

	if (seen_recently(&e))
		return 0;

	emit(&e);

	return 0;
}

// A packet socket is bound to an interface and ethertype. This is tcpdump
// starting a capture, arping, or a DHCP client getting ready. A zero
// protocol in the address keeps the one the socket was created with; if
// that is zero too, the socket receives nothing yet (libpcap binds like that
// once before binding for real), so there is nothing to report.
SEC("kprobe/packet_bind")
int BPF_KPROBE(handle_packet_bind, struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct event e;
	__builtin_memset(&e, 0, sizeof(e));

	e.kind = KIND_CAPTURE;

	fill_process(&e);
	fill_packet_socket(&e, sock);

	struct ll_addr ll;
	__builtin_memset(&ll, 0, sizeof(ll));

	if (addr_len >= (int)sizeof(ll))
		bpf_probe_read_kernel(&ll, sizeof(ll), uaddr);

	if (ll.ifindex)
		e.ifindex = ll.ifindex;

	if (ll.protocol)
		e.ethertype = bpf_ntohs(ll.protocol);

	if (!e.ethertype)
		return 0;

	if (seen_recently(&e))
		return 0;

	emit(&e);

	return 0;
}

// A frame is sent through a packet socket. The destination MAC is in the
// message for datagram-style sockets; raw-style senders put it inside the
// frame themselves, where we don't look.
SEC("kprobe/packet_sendmsg")
int BPF_KPROBE(handle_packet_sendmsg, struct socket *sock, struct msghdr *msg)
{
	struct event e;
	__builtin_memset(&e, 0, sizeof(e));

	e.kind = KIND_OUT;

	fill_process(&e);
	fill_packet_socket(&e, sock);

	const void *name = BPF_CORE_READ(msg, msg_name);
	int namelen = BPF_CORE_READ(msg, msg_namelen);

	if (name && namelen >= (int)sizeof(struct ll_addr)) {
		struct ll_addr ll;
		bpf_probe_read_kernel(&ll, sizeof(ll), name);

		if (ll.ifindex)
			e.ifindex = ll.ifindex;

		if (ll.protocol)
			e.ethertype = bpf_ntohs(ll.protocol);

		__builtin_memcpy(e.mac, ll.addr, sizeof(e.mac));
	}

	if (seen_recently(&e))
		return 0;

	emit(&e);

	return 0;
}

#endif // CONN_MON_PACKET_BPF_H
