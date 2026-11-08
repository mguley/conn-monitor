// SPDX-License-Identifier: GPL-2.0
// Module: TCP. Connections this machine opens (tcp_connect) or accepts
// (inet_csk_accept), and doors opening or shutting (the inet_sock_set_state
// tracepoint).
#ifndef CONN_MON_TCP_BPF_H
#define CONN_MON_TCP_BPF_H

#include "common.bpf.h"

#define TCP_CLOSE 7
#define TCP_LISTEN 10

// Outgoing connections. tcp_connect builds and sends the first packet (the
// SYN) of a connection a process is opening. It runs inside that process's
// connect() call, after the kernel has chosen the local port.
SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_connect, struct sock *sk)
{
	struct event e;
	__builtin_memset(&e, 0, sizeof(e));

	e.kind = KIND_OUT;

	fill_process(&e);
	fill_socket(&e, sk);
	remember_owner(sk, &e);

	emit(&e);

	return 0;
}

// Incoming connections. inet_csk_accept hands a server its next completed
// handshake. When it returns we are inside the server process, and its
// return value is the new connection's socket.
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_accept, struct sock *sk)
{
	if (!sk)
		return 0; // nothing waiting, or an error

	struct event e;
	__builtin_memset(&e, 0, sizeof(e));

	e.kind = KIND_IN;

	fill_process(&e);
	fill_socket(&e, sk);
	remember_owner(sk, &e);

	emit(&e);

	return 0;
}

// Doors. A TCP socket changes state; two transitions happen inside the
// program's own system calls: into LISTEN, from listen() (a door opens), and
// from LISTEN to CLOSE, from close() (it shuts). The socket's own fields give
// the address; the record's arrays are not read directly (the verifier
// rejects copies out of them).
SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	if (ctx->protocol != IPPROTO_TCP)
		return 0;

	const int opening = ctx->newstate == TCP_LISTEN;
	int closing = ctx->oldstate == TCP_LISTEN && ctx->newstate == TCP_CLOSE;

	if (!opening && !closing)
		return 0;

	struct sock *sk = (struct sock *)ctx->skaddr;
	struct event e;
	__builtin_memset(&e, 0, sizeof(e));

	e.kind = opening ? KIND_LISTEN : KIND_UNLISTEN;

	fill_process(&e);
	fill_socket(&e, sk);

	if (opening)
		remember_owner(sk, &e); // so a refused connection to this door is charged to its owner

	emit(&e);

	return 0;
}

#endif // CONN_MON_TCP_BPF_H
