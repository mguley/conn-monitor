// SPDX-License-Identifier: GPL-2.0
// Kernel side of conn-monitor: the one file bpf2go compiles. It pulls in the
// shared toolbox and then one module per responsibility. A module is a set
// of hooks; include it to enable it, leave it out to build without it. The
// Go side attaches whatever hooks end up in the compiled object, so adding
// or removing a module here needs no change in main.go.

#include "common.bpf.h"

#include "tcp.bpf.h"      // TCP connections opened or accepted, doors opened or shut
#include "datagram.bpf.h" // UDP, ICMP, raw and SCTP datagrams sent or received
#include "packet.bpf.h"   // packet sockets: sniffers, ARP, DHCP, below IP
#include "drop.bpf.h"     // packets the kernel throws away, with the reason
#include "exec.bpf.h"     // which program each process id was started as
#include "block.bpf.h"    // rules, decided inside connect() and sendto(); armed by -block
