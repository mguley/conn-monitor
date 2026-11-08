// Turning the raw numbers of a kernel event into words: process and user
// names, interface, protocol and reason names, addresses with or without
// ports, and the two output formats.
package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// Event kinds, matching KIND_* in bpf/common.bpf.h.
const (
	kindOut      = 1 // this machine opened the connection, or sent first
	kindIn       = 2 // this machine accepted the connection, or received first
	kindCapture  = 3 // a packet socket was opened or bound
	kindDropIn   = 4 // an incoming packet was thrown away
	kindDropOut  = 5 // a locally generated packet was thrown away
	kindListen   = 6 // a program started listening on a TCP port
	kindUnlisten = 7 // it stopped
	kindDenied   = 8 // a rule refused a connection attempt
	kindAsk      = 9 // an attempt no rule covered; the default applied
)

// protoNames maps IP protocol numbers to the names shown in the PROTO column.
var protoNames = map[uint8]string{
	1: "icmp", 6: "tcp", 17: "udp", 58: "icmp6", 132: "sctp", 136: "udplite", 255: "raw",
}

// etherNames maps link-layer protocol numbers (ethertypes) to names.
var etherNames = map[uint16]string{
	0x0000: "none", 0x0003: "all", 0x0800: "ipv4", 0x0806: "arp", 0x86dd: "ipv6",
	0x8100: "vlan", 0x88cc: "lldp", 0x888e: "eapol",
}

// connection is one event, enriched with what the kernel side can't know.
type connection struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`  // snap, out, in, listen, unlisten, cap, drop, denied or ask
	Dir       string    `json:"dir"`   // out or in: which way the packet or connection goes
	Proto     string    `json:"proto"` // tcp, udp, icmp, packet, ...
	PID       uint32    `json:"pid,omitzero"`
	Comm      string    `json:"comm,omitzero"`
	Exe       string    `json:"exe,omitzero"`
	User      string    `json:"user,omitzero"`
	Local     string    `json:"local,omitzero"`
	Remote    string    `json:"remote,omitzero"`
	State     string    `json:"state,omitzero"`     // snapshot: ESTABLISHED, LISTEN, UNCONN, ...
	Iface     string    `json:"iface,omitzero"`     // packet sockets and drops
	Ethertype string    `json:"ethertype,omitzero"` // packet sockets: arp, ipv4, all, ...
	MAC       string    `json:"mac,omitzero"`       // packet sockets: destination
	Flags     string    `json:"tcp_flags,omitzero"` // drops of TCP packets: SYN, SYN,ACK, RST, ...
	Reason    string    `json:"reason,omitzero"`    // drops: why the kernel threw it away; decisions: what applied
	Repeats   uint32    `json:"repeats,omitzero"`   // sightings suppressed since the flow was last reported
}

// resolver turns the raw numbers in events into words, caching lookups.
type resolver struct {
	now     func() time.Time
	users   map[uint32]string
	ifaces  map[uint32]string
	reasons map[uint32]string
	exes    *ebpf.Map // pid -> executable path, from the exec module; nil without it
}

// newResolver prepares a resolver that names drop reasons the way the
// running kernel does. exes may be nil when the exec module is left out.
func newResolver(exes *ebpf.Map, stderr io.Writer) *resolver {
	return &resolver{
		now:     time.Now,
		users:   make(map[uint32]string),
		ifaces:  make(map[uint32]string),
		reasons: dropReasons(stderr),
		exes:    exes,
	}
}

// dropReasons reads the names of the kernel's drop reasons from the running
// kernel's type information, so they match this kernel. On failure the
// reasons stay numeric.
func dropReasons(stderr io.Writer) map[uint32]string {
	reasons := make(map[uint32]string)
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		fmt.Fprintln(stderr, "conn-monitor: can't read kernel types, drop reasons will be numeric:", err)
		return reasons
	}

	var e *btf.Enum
	if err := spec.TypeByName("skb_drop_reason", &e); err != nil {
		fmt.Fprintln(stderr, "conn-monitor: no skb_drop_reason in kernel types, drop reasons will be numeric:", err)
		return reasons
	}

	for _, v := range e.Values {
		reasons[uint32(v.Value)] = strings.ToLower(strings.TrimPrefix(v.Name, "SKB_DROP_REASON_"))
	}

	return reasons
}

// enrich turns a raw kernel event into a printable connection.
func (r *resolver) enrich(ev monitorEvent) connection {
	c := connection{Time: r.now(), Proto: protoName(ev), Repeats: ev.Repeats}
	switch ev.Kind {
	case kindOut:
		c.Kind, c.Dir = "out", "out"
	case kindIn:
		c.Kind, c.Dir = "in", "in"
	case kindCapture:
		c.Kind, c.Dir = "cap", "in"
	case kindDropIn:
		c.Kind, c.Dir = "drop", "in"
	case kindDropOut:
		c.Kind, c.Dir = "drop", "out"
	case kindListen:
		c.Kind, c.Dir = "listen", "in"
	case kindUnlisten:
		c.Kind, c.Dir = "unlisten", "in"
	case kindDenied:
		c.Kind, c.Dir = "denied", "out"
	case kindAsk:
		c.Kind, c.Dir = "ask", "out"
	default:
		c.Kind, c.Dir = "?", "?"
	}

	// Drops of packets that never met a socket have no program behind them.
	if ev.Tgid != 0 {
		c.PID = ev.Tgid
		c.Comm = cString(ev.Comm[:])
		c.User = r.userName(ev.Uid)
		// The kernel named the thread that made the call, which in a
		// multithreaded program can be "Socket Thread" rather than the
		// program. /proc has the process's own name while it is alive.
		if b, err := os.ReadFile(procPath(ev.Tgid, "comm")); err == nil {
			c.Comm = strings.TrimSpace(string(b))
		}
		c.Exe = r.exePath(ev.Tgid)
	}

	if ev.Family == unix.AF_PACKET {
		c.Iface = r.ifaceName(ev.Ifindex)
		c.Ethertype = etherName(ev.Ethertype)
		if mac := net.HardwareAddr(ev.Mac[:]); ev.Kind == kindOut && !bytes.Equal(mac, make([]byte, 6)) {
			c.MAC = mac.String()
		}
		return c
	}

	ports := hasPorts(ev.Proto, ev.Socktype)
	c.Local = addrText(ev.Family, ev.Saddr, ev.Sport, ports)
	c.Remote = addrText(ev.Family, ev.Daddr, ev.Dport, ports)

	switch ev.Kind {
	case kindListen, kindUnlisten:
		c.Remote = "" // a door has no peer yet
	case kindDropIn, kindDropOut:
		c.Iface = r.ifaceName(ev.Ifindex)
		c.Reason = r.reasonName(ev.Reason)
		c.Flags = tcpFlags(ev.Tcpflags)
	case kindDenied, kindAsk:
		c.Local = "" // decided before the local side of the socket exists
		c.Reason = verdictText(ev)
	}
	return c
}

// verdictText says what the block module did with an attempt, and why.
func verdictText(ev monitorEvent) string {
	what := "allowed"
	if ev.Verdict == ruleDeny {
		what = "denied"
	}

	if ev.Matched != 0 {
		return what + " by rule"
	}

	return what + " by default, no rule"
}

// procPath is the path of one file of a process in /proc.
func procPath(pid uint32, file string) string {
	return filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), file)
}

// exePath finds a process's executable: from /proc while it is alive, and
// from the exec module's record of its exec() after it has gone. Without
// that module there is no record, and the path is simply empty.
func (r *resolver) exePath(pid uint32) string {
	if exe, err := os.Readlink(procPath(pid, "exe")); err == nil {
		return strings.TrimSuffix(exe, " (deleted)")
	}
	if r.exes == nil {
		return ""
	}

	var p [128]byte
	if err := r.exes.Lookup(pid, &p); err == nil {
		return cBytes(p[:])
	}

	return ""
}

// protoName names the protocol for the PROTO column. A raw socket carries
// whatever protocol the program asked for, so it is marked as raw.
func protoName(ev monitorEvent) string {
	if ev.Family == unix.AF_PACKET {
		return "packet"
	}

	name, ok := protoNames[ev.Proto]
	if !ok {
		name = "ip" + strconv.Itoa(int(ev.Proto))
	}

	if ev.Socktype == unix.SOCK_RAW && ev.Proto != unix.IPPROTO_RAW {
		name = "raw-" + name
	}

	return name
}

// hasPorts says whether a protocol, on this kind of socket, carries ports.
func hasPorts(proto, socktype uint8) bool {
	switch proto {
	case unix.IPPROTO_TCP, unix.IPPROTO_UDP, unix.IPPROTO_SCTP, unix.IPPROTO_UDPLITE:
		return socktype != unix.SOCK_RAW
	}
	return false
}

// addrText renders an address with its port, or without one for protocols
// that have none.
func addrText(family uint16, raw [16]uint8, port uint16, withPort bool) string {
	ap := addrPort(family, raw, port)
	if withPort {
		return ap.String()
	}
	return ap.Addr().String()
}

// addrPort assembles an address from the raw bytes the kernel gave us. IPv4
// uses the first 4 bytes. IPv6 sockets carrying IPv4 traffic (::ffff:a.b.c.d)
// are unmapped so they print as plain IPv4.
func addrPort(family uint16, raw [16]uint8, port uint16) netip.AddrPort {
	var addr netip.Addr
	if family == unix.AF_INET {
		addr = netip.AddrFrom4([4]byte(raw[:4]))
	} else {
		addr = netip.AddrFrom16(raw).Unmap()
	}
	return netip.AddrPortFrom(addr, port)
}

// etherName names a link-layer protocol number.
func etherName(t uint16) string {
	if name, ok := etherNames[t]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", t)
}

// reasonName names a drop reason, falling back to its number.
func (r *resolver) reasonName(reason uint32) string {
	if name, ok := r.reasons[reason]; ok {
		return name
	}
	return "reason-" + strconv.FormatUint(uint64(reason), 10)
}

// tcpFlags spells out the flag byte of a TCP header.
func tcpFlags(b uint8) string {
	var set []string
	for _, f := range []struct {
		bit  uint8
		name string
	}{{0x02, "SYN"}, {0x10, "ACK"}, {0x01, "FIN"}, {0x04, "RST"}, {0x08, "PSH"}, {0x20, "URG"}} {
		if b&f.bit != 0 {
			set = append(set, f.name)
		}
	}
	return strings.Join(set, ",")
}

// ifaceName resolves an interface index once and caches it. Index 0 means
// "all interfaces" for a packet socket.
func (r *resolver) ifaceName(index uint32) string {
	if index == 0 {
		return "any"
	}
	if name, ok := r.ifaces[index]; ok {
		return name
	}

	name := "if" + strconv.FormatUint(uint64(index), 10)
	if ifi, err := net.InterfaceByIndex(int(index)); err == nil {
		name = ifi.Name
	}

	r.ifaces[index] = name
	return name
}

// userName resolves a uid once and caches it; unknown uids stay numeric.
func (r *resolver) userName(uid uint32) string {
	if name, ok := r.users[uid]; ok {
		return name
	}

	name := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}

	r.users[uid] = name
	return name
}

// cString converts a NUL-terminated C char array to a Go string.
func cString(b []int8) string {
	var sb strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		sb.WriteByte(byte(c))
	}
	return sb.String()
}

// cBytes converts a NUL-terminated byte array to a Go string.
func cBytes(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// printText prints one aligned line per event.
func printText(w io.Writer, c connection) error {
	who, usr := "-", "-"
	if c.PID != 0 {
		who = fmt.Sprintf("%s[%d]", c.Comm, c.PID)
		usr = c.User
	}

	arrow := "->"
	if c.Dir == "in" {
		arrow = "<-"
	}

	var what string
	switch {
	case c.Kind == "cap":
		what = c.Iface + " " + c.Ethertype
	case c.Proto == "packet":
		mac := c.MAC
		if mac == "" {
			mac = "?"
		}
		what = c.Iface + " -> " + mac + " " + c.Ethertype
	case c.Local == "":
		what = "-> " + c.Remote
	case c.Remote == "":
		what = c.Local
	default:
		what = c.Local + " " + arrow + " " + c.Remote
	}

	if c.State != "" {
		what += " " + c.State
	}
	if c.Flags != "" {
		what += " " + c.Flags
	}
	if c.Repeats > 0 {
		what += fmt.Sprintf(" [x%d]", c.Repeats)
	}

	tail := c.Exe
	if c.Reason != "" {
		tail = c.Reason
		if c.Iface != "" {
			tail += " (" + c.Iface + ")"
		}
		if c.Exe != "" {
			tail += "  " + c.Exe
		}
	}

	_, err := fmt.Fprintf(w, "%s  %-8s  %-9s  %-22s  %-20s  %s  %s\n",
		c.Time.Format("15:04:05.000"), c.Kind, c.Proto, who, usr, what, tail)
	return err
}

// printSummary lists the flows whose repeats were counted but not yet
// reported when conn-monitor stopped, read straight from the kernel's map.
func printSummary(w io.Writer, flows *ebpf.Map, r *resolver) {
	if flows == nil {
		return
	}

	var key monitorFlowKey
	var stat monitorFlowStat
	var lines []string
	it := flows.Iterate()
	for it.Next(&key, &stat) {
		if stat.Count == 0 {
			continue
		}
		lines = append(lines, r.summaryLine(key, stat))
	}

	if err := it.Err(); err != nil {
		fmt.Fprintln(w, "conn-monitor: reading flows:", err)
	}

	if len(lines) == 0 {
		return
	}

	slices.Sort(lines)
	fmt.Fprintln(w, "conn-monitor: repeats not yet reported when stopped (count, kind, protocol, program, target):")
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}

// summaryLine renders one flows entry.
func (r *resolver) summaryLine(key monitorFlowKey, stat monitorFlowStat) string {
	kind := "flow"
	switch key.Kind {
	case kindCapture:
		kind = "cap"
	case kindDropIn:
		kind = "drop in"
	case kindDropOut:
		kind = "drop out"
	case kindDenied:
		kind = "denied"
	case kindAsk:
		kind = "ask"
	}

	proto := "packet"
	if key.Family != unix.AF_PACKET {
		proto = protoName(monitorEvent{Proto: key.Proto})
	}

	who := "-"
	if key.Tgid != 0 {
		who = fmt.Sprintf("pid %d", key.Tgid)
		if exe := r.exePath(key.Tgid); exe != "" {
			who = fmt.Sprintf("%s[%d]", filepath.Base(exe), key.Tgid)
		}
	}

	var target string
	if key.Family == unix.AF_PACKET {
		target = r.ifaceName(key.Ifindex) + " " + etherName(key.Ethertype)
	} else {
		target = addrText(key.Family, key.Daddr, key.Port, key.Port != 0)
	}
	if key.Reason != 0 {
		target += "  " + r.reasonName(key.Reason) + " (" + r.ifaceName(key.Ifindex) + ")"
	}

	return fmt.Sprintf("  x%-7d %-9s %-9s %-22s %s", stat.Count, kind, proto, who, target)
}
