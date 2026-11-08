// SPDX-License-Identifier: GPL-2.0
// Module: exec memory. Records the path every process was started from, so
// the Go side can still name a program after it has exited. This module owns
// its map; the Go side works without it when the module is left out.
#ifndef CONN_MON_EXEC_BPF_H
#define CONN_MON_EXEC_BPF_H

#include "common.bpf.h"

// exe_path is the path a program was started from, as given to execve(2).
struct exe_path {
	char path[128];
};

// exes is keyed by process id.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct exe_path);
} exes SEC(".maps");

// A process starts running a new program. The record carries the path that
// was executed as a "data location": an offset into the record where the
// string lives.
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct exe_path p;
	__builtin_memset(&p, 0, sizeof(p));

	const unsigned int off = ctx->__data_loc_filename & 0xFFFF;

	bpf_probe_read_kernel_str(p.path, sizeof(p.path), (void *)ctx + off);
	bpf_map_update_elem(&exes, &tgid, &p, 0);

	return 0;
}

#endif // CONN_MON_EXEC_BPF_H
