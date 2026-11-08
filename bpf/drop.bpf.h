// SPDX-License-Identifier: GPL-2.0
// Module: drops. The kfree_skb tracepoint fires for every packet the kernel
// throws away, with a reason; this module turns each into an event with the
// packet's addresses, direction, interface and, where a socket we have seen
// is involved, the program behind it.
#ifndef CONN_MON_DROP_BPF_H
#define CONN_MON_DROP_BPF_H

#include "common.bpf.h"

// Incoming packets carry the index of the interface they arrived on;
// locally generated ones don't, and before they reach the device layer only
// their route knows the device.
SEC("tracepoint/skb/kfree_skb")
int handle_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
	__be16 wire = BPF_CORE_READ(skb, protocol);

	if (wire != bpf_htons(ETH_P_IP) && wire != bpf_htons(ETH_P_IPV6))
		return 0; // ARP, LLDP and the like: not what we watch

	struct event e;
	__builtin_memset(&e, 0, sizeof(e));

	e.reason = ctx->reason;

	const __u32 iif = BPF_CORE_READ(skb, skb_iif);

	if (iif) {
		e.kind = KIND_DROP_IN;
		e.ifindex = iif;
	} else {
		e.kind = KIND_DROP_OUT;
		e.ifindex = BPF_CORE_READ(skb, dev, ifindex);

		if (!e.ifindex) {
			// The low bit of _skb_refdst is a flag, not part of the address.
			struct dst_entry *dst = (struct dst_entry *)(BPF_CORE_READ(skb, _skb_refdst) & ~1UL);
			if (dst)
				e.ifindex = BPF_CORE_READ(dst, dev, ifindex);
		}
	}

	if (parse_headers(&e, skb, iif != 0) < 0)
		return 0;

	// Charge the drop to a program if a socket we have seen is involved:
	// the sender's socket for outgoing packets, or the receiving socket,
	// which the kernel names when the drop happened after it looked one up.
	struct sock *sk = BPF_CORE_READ(skb, sk);
	if (!sk && bpf_core_field_exists(ctx->rx_sk))
		sk = (struct sock *)ctx->rx_sk;

	if (sk)
		recall_owner(&e, sk);

	if (seen_recently(&e))
		return 0;

	emit(&e);

	return 0;
}

#endif // CONN_MON_DROP_BPF_H
