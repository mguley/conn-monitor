// SPDX-License-Identifier: GPL-2.0
// The toolbox every module uses: the event, the shared maps, and the helpers
// that fill events and decide whether to report them. Nothing in here is a
// hook; modules add those.
#ifndef CONN_MON_COMMON_BPF_H
#define CONN_MON_COMMON_BPF_H

// vmlinux.h is machine-generated; silence its harmless forward-declaration warnings.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Some kernel helpers are only available to GPL-licensed programs.
char LICENSE[] SEC("license") = "GPL";

// Constants from the usual C headers; vmlinux.h carries types, not macros.
#define AF_INET 2
#define AF_INET6 10
#define SOCK_RAW 3
#define ETH_P_IP 0x0800   // skb->protocol: the packet is IPv4
#define ETH_P_IPV6 0x86DD // skb->protocol: the packet is IPv6
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define BPF_NOEXIST 1 // bpf_map_update_elem: insert only, fail if the key exists

// Datagram flows, drops, packet-socket openings and rule decisions are
// reported at most once per this many nanoseconds; repeats in between are
// counted. TCP connections and listen events are always reported.
#define FLOW_WINDOW_NS (60ULL * 1000000000ULL)

// The kinds of event. Numbers are shared with the Go side; add new ones at
// the end.
enum kind {
	KIND_OUT = 1,      // this machine opened the connection, or sent first
	KIND_IN = 2,       // this machine accepted the connection, or received first
	KIND_CAPTURE = 3,  // a packet socket was opened or bound: sniffing, ARP, DHCP
	KIND_DROP_IN = 4,  // an incoming packet was thrown away
	KIND_DROP_OUT = 5, // a locally generated packet was thrown away
	KIND_LISTEN = 6,   // a program started listening on a TCP port
	KIND_UNLISTEN = 7, // it stopped
	KIND_DENIED = 8,   // a rule refused a connection attempt
	KIND_ASK = 9,      // an attempt no rule covered; the default applied
};

// One event. bpf2go generates the matching Go struct from this definition,
// so keep the layout simple (no implicit padding).
struct event {
	__u32 tgid;      // process id as shown by ps; 0 when no program is involved
	__u32 uid;       // user the process runs as
	__u8 saddr[16];  // local address; IPv4 uses the first 4 bytes
	__u8 daddr[16];  // remote address
	__u16 sport;     // local port, host byte order (0 when the protocol has none)
	__u16 dport;     // remote port, host byte order
	__u16 family;    // AF_INET, AF_INET6 or AF_PACKET
	__u8 kind;       // enum kind
	__u8 proto;      // IP protocol: 6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6, 132 SCTP
	__u8 socktype;   // 1 stream, 2 datagram, 3 raw (SOCK_* in socket(2))
	__u8 tcpflags;   // drops of TCP packets: the flag byte (SYN 0x02, ACK 0x10, RST 0x04)
	__u16 ethertype; // packet sockets: link-layer protocol (0x0806 ARP, 0x0003 all)
	__u32 ifindex;   // packet sockets and drops: the network interface
	__u32 reason;    // drops: the kernel's skb_drop_reason value
	__u8 mac[6];     // packet sockets: destination hardware address
	__u8 verdict;    // rules: 1 allowed, 2 denied
	__u8 matched;    // rules: 1 when a rule decided, 0 when the default did
	__u32 repeats;   // sightings of the same flow suppressed since it was last reported
	char comm[16];   // name of the calling thread, cut to 15 characters
};

// Nothing references struct event by type, so this keeps it in the compiled
// object's type information for bpf2go to find.
const struct event *unused_event __attribute__((unused));

// The queue the kernel side writes to and the Go side reads from.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// flow_key identifies a repeating event for de-duplication: which program,
// which protocol, which remote host (or interface, MAC and ethertype for
// packet sockets), and for drops and rule decisions which reason and which
// port. Ports are left out of ordinary flows on purpose: a DNS resolver uses
// a fresh local port per query and a server sees a new remote port per client
// packet. For drops and decisions the port is the point: a port scan becomes
// one line per port tried.
struct flow_key {
	__u32 tgid;
	__u16 family;
	__u8 proto;
	__u8 kind; // 0 for ordinary flows; the kind for drops, captures and decisions
	__u8 daddr[16];
	__u32 ifindex;
	__u32 reason;
	__u16 ethertype;
	__u8 mac[6];
	__u16 port; // drops: our port for incoming, the remote port for outgoing; decisions: the remote port
	__u8 pad[2];
};

// flow_stat is what flows remembers per flow.
struct flow_stat {
	__u64 last;  // when the flow was last reported, in ns since boot
	__u64 count; // sightings suppressed since then
};

// flows is LRU: when the map is full, the kernel evicts the least recently
// used entry, so there is nothing to clean up. The Go side reads it on exit
// to print the counts that were still pending.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct flow_key);
	__type(value, struct flow_stat);
} flows SEC(".maps");

// owner is what we know about the program behind a socket, remembered so a
// packet dropped later (from a timer, or on arrival, with no useful process
// context) can still be charged to the right program.
struct owner {
	__u32 tgid;
	__u32 uid;
	char comm[16];
};

// owners is keyed by the kernel's socket pointer.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct owner);
} owners SEC(".maps");

// ports is the start of both a TCP and a UDP header.
struct ports {
	__be16 source;
	__be16 dest;
};

// All socket hooks run inside the process that made the call, so "current"
// is the process we want to report.
static __always_inline void fill_process(struct event *e)
{
	e->tgid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// fill_local records the socket's local address and port, in the address
// family already set in e->family.
static __always_inline void fill_local(struct event *e, struct sock *sk)
{
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num); // host byte order
	__builtin_memset(e->saddr, 0, sizeof(e->saddr));

	if (e->family == AF_INET) {
		__u32 a = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(e->saddr, &a, 4);
	} else {
		BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_v6_rcv_saddr);
	}
}

// fill_peer_from_sock records the remote address and port the socket is
// connected to (all zeros for an unconnected datagram socket).
static __always_inline void fill_peer_from_sock(struct event *e, struct sock *sk)
{
	e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)); // network byte order
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));

	if (e->family == AF_INET) {
		__u32 a = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(e->daddr, &a, 4);
	} else {
		BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr);
	}
}

// fill_socket records family, type, protocol and both ends of a socket.
// BPF_CORE_READ is a checked read of kernel memory plus the CO-RE offset
// adjustment for the running kernel. A raw socket keeps its protocol number
// where a port would be, so its "ports" are cleared.
static __always_inline void fill_socket(struct event *e, struct sock *sk)
{
	e->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	e->socktype = BPF_CORE_READ(sk, sk_type);
	e->proto = BPF_CORE_READ(sk, sk_protocol);

	fill_local(e, sk);
	fill_peer_from_sock(e, sk);

	if (e->socktype == SOCK_RAW)
		e->sport = e->dport = 0;
}

// remember_owner stores the program behind a socket for recall_owner.
static __always_inline void remember_owner(struct sock *sk, const struct event *e)
{
	const __u64 key = (__u64)sk;
	struct owner o;
	__builtin_memset(&o, 0, sizeof(o));

	o.tgid = e->tgid;
	o.uid = e->uid;

	__builtin_memcpy(o.comm, e->comm, sizeof(o.comm));
	bpf_map_update_elem(&owners, &key, &o, 0); // 0 = BPF_ANY: insert or update
}

// recall_owner fills in the program behind a socket, if we have seen it.
static __always_inline void recall_owner(struct event *e, struct sock *sk)
{
	const __u64 key = (__u64)sk;
	struct owner *o = bpf_map_lookup_elem(&owners, &key);
	if (!o)
		return;

	e->tgid = o->tgid;
	e->uid = o->uid;

	__builtin_memcpy(e->comm, o->comm, sizeof(e->comm));
}

// seen_recently decides whether to report an event now. The first sighting
// of a flow is reported; sightings within the window are counted instead;
// the first sighting after the window is reported again with that count in
// e->repeats. The insert-only update makes two CPUs seeing a new flow at the
// same instant agree on who reports it.
static __always_inline int seen_recently(struct event *e)
{
	struct flow_key key;
	__builtin_memset(&key, 0, sizeof(key));

	key.tgid = e->tgid;
	key.family = e->family;
	key.proto = e->proto;

	__builtin_memcpy(key.daddr, e->daddr, sizeof(key.daddr));

	key.ifindex = e->ifindex;
	key.reason = e->reason;
	key.ethertype = e->ethertype;

	__builtin_memcpy(key.mac, e->mac, sizeof(key.mac));

	if (e->kind == KIND_DROP_IN) {
		key.kind = e->kind;
		key.port = e->sport; // which of our ports was probed
	} else if (e->kind == KIND_DROP_OUT || e->kind == KIND_DENIED || e->kind == KIND_ASK) {
		key.kind = e->kind;
		key.port = e->dport; // which remote port we tried
	} else if (e->kind == KIND_CAPTURE) {
		key.kind = e->kind;
	}

	const __u64 now = bpf_ktime_get_ns();
	struct flow_stat *s = bpf_map_lookup_elem(&flows, &key);

	if (!s) {
		const struct flow_stat fresh = { .last = now, .count = 0 };
		if (bpf_map_update_elem(&flows, &key, &fresh, BPF_NOEXIST) == 0)
			return 0; // first sighting: report it

		s = bpf_map_lookup_elem(&flows, &key); // another CPU inserted it just now
		if (!s)
			return 0;
	}

	if (now - s->last < FLOW_WINDOW_NS) {
		__sync_fetch_and_add(&s->count, 1);
		return 1;
	}

	e->repeats = s->count;
	s->count = 0;
	s->last = now;
	return 0;
}

// emit copies a finished event into the ring buffer. If the buffer is full
// the event is lost; stalling the kernel is never an option.
static __always_inline void emit(const struct event *e)
{
	bpf_ringbuf_output(&events, (void *)e, sizeof(*e), 0);
}

// parse_headers fills family, protocol, addresses, ports and TCP flags from
// the headers a packet buffer (the skb) still carries: the IP header sits at
// head + network_header, the TCP or UDP header at head + transport_header.
// incoming says which end is ours. Returns -1 for anything that isn't IP, or
// whose headers were never built (a buffer freed before being sent).
static __always_inline int parse_headers(struct event *e, struct sk_buff *skb, const int incoming)
{
	const unsigned char *head = BPF_CORE_READ(skb, head);
	const __u16 nh = BPF_CORE_READ(skb, network_header);
	const __u16 th = BPF_CORE_READ(skb, transport_header);
	const __be16 wire = BPF_CORE_READ(skb, protocol);

	if (nh == 0)
		return -1; // a real packet always has headroom in front of its IP header

	if (wire == bpf_htons(ETH_P_IP)) {
		struct iphdr ip;
		bpf_probe_read_kernel(&ip, sizeof(ip), head + nh);
		e->family = AF_INET;
		e->proto = ip.protocol;

		if (incoming) {
			__builtin_memcpy(e->saddr, &ip.daddr, 4); // the packet's destination is us
			__builtin_memcpy(e->daddr, &ip.saddr, 4); // its source is the peer
		} else {
			__builtin_memcpy(e->saddr, &ip.saddr, 4);
			__builtin_memcpy(e->daddr, &ip.daddr, 4);
		}
	} else if (wire == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6;
		bpf_probe_read_kernel(&ip6, sizeof(ip6), head + nh);
		e->family = AF_INET6;
		e->proto = ip6.nexthdr;

		if (incoming) {
			__builtin_memcpy(e->saddr, &ip6.daddr, 16);
			__builtin_memcpy(e->daddr, &ip6.saddr, 16);
		} else {
			__builtin_memcpy(e->saddr, &ip6.saddr, 16);
			__builtin_memcpy(e->daddr, &ip6.daddr, 16);
		}
	} else {
		return -1;
	}

	// Ports only mean something for TCP and UDP, and only once the kernel has
	// set the transport header (0xFFFF means "not yet"; a value at or before
	// the IP header means the same).
	if ((e->proto == IPPROTO_TCP || e->proto == IPPROTO_UDP) && th != 0xFFFF && th > nh) {
		struct ports p;
		bpf_probe_read_kernel(&p, sizeof(p), head + th);

		e->sport = bpf_ntohs(incoming ? p.dest : p.source);
		e->dport = bpf_ntohs(incoming ? p.source : p.dest);

		if (e->proto == IPPROTO_TCP)
			bpf_probe_read_kernel(&e->tcpflags, 1, head + th + 13); // byte 13 of a TCP header
	}
	return 0;
}

#endif // CONN_MON_COMMON_BPF_H
