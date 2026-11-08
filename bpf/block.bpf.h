// SPDX-License-Identifier: GPL-2.0
// Module: rules. Decides, inside the program's own connect() or sendto()
// call, whether a new TCP connection or UDP datagram may go out, by program
// and destination. A refused attempt fails at once with EPERM; no packet is
// ever built, so nothing needs to be held or dropped. The hooks are loaded
// with the rest but only attached when conn-monitor is started with -block.
#ifndef CONN_MON_BLOCK_BPF_H
#define CONN_MON_BLOCK_BPF_H

#include "common.bpf.h"

#define RULE_ALLOW 1
#define RULE_DENY 2

// rule_key is what a rule applies to. A program is identified the way the
// kernel identifies a file: by the device its file system lives on and its
// inode number, the two numbers stat(2) reports. Every path that leads to
// the same file is the same program, so a symlink (/usr/bin/python3 for
// python3.14, /bin for /usr/bin) can't make a rule miss. "Any" is spelled
// with zeros: ino 0 for any program, an all-zero daddr with family 0 for any
// address, dport 0 for any port. The Go side writes the keys; try_four looks
// the specific ones up before the general ones.
struct rule_key {
	__u64 ino;      // inode number of the program's executable, 0 for any
	__u32 dev;      // device of the file system it is on, in the kernel's encoding
	__u16 dport;    // destination port, host byte order, 0 for any
	__u8 family;    // AF_INET or AF_INET6 when daddr is set, 0 for any address
	__u8 pad;
	__u8 daddr[16]; // destination; IPv4 uses the first 4 bytes
};

// rule is the decision, how often it was taken, and the program's path as
// the rules file spells it. The path is kept for printing only; the kernel
// never looks at it.
struct rule {
	__u8 action; // RULE_ALLOW or RULE_DENY
	__u8 pad[7];
	__u64 hits;
	char exe[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct rule_key);
	__type(value, struct rule);
} rules SEC(".maps");

// policy is what applies when no rule does: one entry in settings, written
// by the Go side. (The struct and the map need different names: bpf2go
// looks types up by name, and a map is a global variable.)
struct policy {
	__u8 default_action;
	__u8 pad[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct policy);
} settings SEC(".maps");

// current_exe fills in the file the calling process was started from. The
// task's memory descriptor keeps the executable open as exe_file, the same
// file /proc/<pid>/exe points to. Kernel threads have no memory descriptor
// and get zeros, which only the "any program" rules match.
static __always_inline void current_exe(struct rule_key *key)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
	if (!inode)
		return;
	key->ino = BPF_CORE_READ(inode, i_ino);
	key->dev = BPF_CORE_READ(inode, i_sb, s_dev);
}

// try_four looks a key up four ways, most specific first: address and port,
// address only, port only, neither. It leaves the key as it found it when
// nothing matched, so the caller can try again for any program.
static __always_inline struct rule *try_four(struct rule_key *key)
{
	__u16 dport = key->dport;
	__u8 family = key->family;
	__u8 daddr[16];
	__builtin_memcpy(daddr, key->daddr, sizeof(daddr));

	struct rule *r = bpf_map_lookup_elem(&rules, key);
	if (r)
		return r;

	key->dport = 0;
	r = bpf_map_lookup_elem(&rules, key);
	if (r)
		return r;

	key->dport = dport;
	key->family = 0;
	__builtin_memset(key->daddr, 0, sizeof(key->daddr));
	r = bpf_map_lookup_elem(&rules, key);
	if (r)
		return r;

	key->dport = 0;
	r = bpf_map_lookup_elem(&rules, key);
	key->dport = dport;
	key->family = family;

	__builtin_memcpy(key->daddr, daddr, sizeof(daddr));
	return r;
}

// decide is the body of the four hooks. It returns 1 to let the kernel go
// on and 0 to refuse, in which case the program's connect() or sendto()
// fails with EPERM. Refusals and attempts no rule covered are reported;
// attempts a rule allows are already reported by the TCP and datagram
// modules as they happen.
static __always_inline int decide(struct bpf_sock_addr *ctx, __u16 family)
{
	// The context's fields must be read whole, 4 bytes each; the barriers
	// stop the compiler from shortening a load to the byte we end up keeping.
	__u32 proto = ctx->protocol;
	__u32 type = ctx->type;
	__u32 port = ctx->user_port;
	barrier_var(proto);
	barrier_var(type);
	barrier_var(port);

	struct event e;
	__builtin_memset(&e, 0, sizeof(e));
	e.family = family;
	e.proto = proto;
	e.socktype = type;
	e.dport = bpf_ntohs((__u16)port);

	if (family == AF_INET) {
		__u32 a = ctx->user_ip4;
		__builtin_memcpy(e.daddr, &a, 4);
	} else {
		__u32 a0 = ctx->user_ip6[0];
		__u32 a1 = ctx->user_ip6[1];
		__u32 a2 = ctx->user_ip6[2];
		__u32 a3 = ctx->user_ip6[3];
		if (a0 == 0 && a1 == 0 && a2 == bpf_htonl(0xffff)) {
			e.family = AF_INET; // an IPv6 socket talking to an IPv4 address
			__builtin_memcpy(e.daddr, &a3, 4);
		} else {
			__builtin_memcpy(e.daddr, &a0, 4);
			__builtin_memcpy(e.daddr + 4, &a1, 4);
			__builtin_memcpy(e.daddr + 8, &a2, 4);
			__builtin_memcpy(e.daddr + 12, &a3, 4);
		}
	}

	fill_process(&e);

	// The program's own rules first, then the ones for any program.
	struct rule_key key;
	__builtin_memset(&key, 0, sizeof(key));

	key.family = e.family;
	__builtin_memcpy(key.daddr, e.daddr, sizeof(key.daddr));

	key.dport = e.dport;
	current_exe(&key);

	struct rule *r = NULL;
	if (key.ino)
		r = try_four(&key);
	if (!r) {
		key.ino = 0;
		key.dev = 0;
		r = try_four(&key);
	}

	__u8 action = RULE_ALLOW;
	__u32 zero = 0;
	struct policy *s = bpf_map_lookup_elem(&settings, &zero);

	if (s)
		action = s->default_action;
	if (r) {
		action = r->action;
		e.matched = 1;
		__sync_fetch_and_add(&r->hits, 1);
	}

	e.verdict = action;

	if (!r)
		e.kind = KIND_ASK;
	else if (action == RULE_DENY)
		e.kind = KIND_DENIED;
	if (e.kind && !seen_recently(&e))
		emit(&e);

	return action == RULE_DENY ? 0 : 1;
}

// The four hooks: connect() of TCP and connected UDP sockets, and sendto()
// of unconnected UDP sockets, for IPv4 and IPv6. The kernel runs them before
// anything else happens to the attempt.
SEC("cgroup/connect4")
int block_connect4(struct bpf_sock_addr *ctx)
{
	return decide(ctx, AF_INET);
}

SEC("cgroup/connect6")
int block_connect6(struct bpf_sock_addr *ctx)
{
	return decide(ctx, AF_INET6);
}

SEC("cgroup/sendmsg4")
int block_sendmsg4(struct bpf_sock_addr *ctx)
{
	return decide(ctx, AF_INET);
}

SEC("cgroup/sendmsg6")
int block_sendmsg6(struct bpf_sock_addr *ctx)
{
	return decide(ctx, AF_INET6);
}

#endif // CONN_MON_BLOCK_BPF_H
