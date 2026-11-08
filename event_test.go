package main

import (
	"net/netip"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAddrPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		family uint16
		raw    [16]uint8
		port   uint16
		want   string
	}{
		{name: "ipv4", family: unix.AF_INET, raw: [16]uint8{127, 0, 0, 1}, port: 53, want: "127.0.0.1:53"},
		{name: "ipv6", family: unix.AF_INET6, raw: [16]uint8{15: 1}, port: 443, want: "[::1]:443"},
		{name: "ipv4 inside ipv6", family: unix.AF_INET6, raw: [16]uint8{10: 0xff, 11: 0xff, 12: 10, 15: 5}, port: 22, want: "10.0.0.5:22"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, want := addrPort(tt.family, tt.raw, tt.port), netip.MustParseAddrPort(tt.want); got != want {
				t.Errorf("addrPort(%d, %v, %d) = %v, want %v", tt.family, tt.raw, tt.port, got, want)
			}
		})
	}
}

func TestAddrText(t *testing.T) {
	t.Parallel()
	raw := [16]uint8{8, 8, 8, 8}
	if got, want := addrText(unix.AF_INET, raw, 53, true), "8.8.8.8:53"; got != want {
		t.Errorf("addrText(with port) = %q, want %q", got, want)
	}
	if got, want := addrText(unix.AF_INET, raw, 0, false), "8.8.8.8"; got != want {
		t.Errorf("addrText(without port) = %q, want %q", got, want)
	}
}

func TestHasPorts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		proto    uint8
		socktype uint8
		want     bool
	}{
		{name: "tcp stream", proto: 6, socktype: 1, want: true},
		{name: "udp datagram", proto: 17, socktype: 2, want: true},
		{name: "sctp", proto: 132, socktype: 1, want: true},
		{name: "icmp", proto: 1, socktype: 2, want: false},
		{name: "raw tcp", proto: 6, socktype: 3, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasPorts(tt.proto, tt.socktype); got != tt.want {
				t.Errorf("hasPorts(%d, %d) = %v, want %v", tt.proto, tt.socktype, got, tt.want)
			}
		})
	}
}

func TestProtoName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ev   monitorEvent
		want string
	}{
		{name: "tcp", ev: monitorEvent{Proto: 6, Socktype: 1}, want: "tcp"},
		{name: "udp", ev: monitorEvent{Proto: 17, Socktype: 2}, want: "udp"},
		{name: "ping socket", ev: monitorEvent{Proto: 1, Socktype: 2}, want: "icmp"},
		{name: "raw icmp", ev: monitorEvent{Proto: 1, Socktype: 3}, want: "raw-icmp"},
		{name: "raw ip", ev: monitorEvent{Proto: 255, Socktype: 3}, want: "raw"},
		{name: "unknown", ev: monitorEvent{Proto: 47, Socktype: 3}, want: "raw-ip47"},
		{name: "packet socket", ev: monitorEvent{Family: unix.AF_PACKET, Socktype: 3}, want: "packet"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := protoName(tt.ev); got != tt.want {
				t.Errorf("protoName(%+v) = %q, want %q", tt.ev, got, tt.want)
			}
		})
	}
}

func TestVerdictText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ev   monitorEvent
		want string
	}{
		{name: "rule denied", ev: monitorEvent{Verdict: ruleDeny, Matched: 1}, want: "denied by rule"},
		{name: "rule allowed", ev: monitorEvent{Verdict: ruleAllow, Matched: 1}, want: "allowed by rule"},
		{name: "default allowed", ev: monitorEvent{Verdict: ruleAllow}, want: "allowed by default, no rule"},
		{name: "default denied", ev: monitorEvent{Verdict: ruleDeny}, want: "denied by default, no rule"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := verdictText(tt.ev); got != tt.want {
				t.Errorf("verdictText(%+v) = %q, want %q", tt.ev, got, tt.want)
			}
		})
	}
}

func TestTCPFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		b    uint8
		want string
	}{
		{name: "none", b: 0, want: ""},
		{name: "syn", b: 0x02, want: "SYN"},
		{name: "syn-ack", b: 0x12, want: "SYN,ACK"},
		{name: "rst-ack", b: 0x14, want: "ACK,RST"},
		{name: "fin-psh-ack", b: 0x19, want: "ACK,FIN,PSH"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tcpFlags(tt.b); got != tt.want {
				t.Errorf("tcpFlags(%#x) = %q, want %q", tt.b, got, tt.want)
			}
		})
	}
}

func TestEtherName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   uint16
		want string
	}{
		{in: 0x0806, want: "arp"},
		{in: 0x0003, want: "all"},
		{in: 0x1234, want: "0x1234"},
	}
	for _, tt := range tests {
		if got := etherName(tt.in); got != tt.want {
			t.Errorf("etherName(%#04x) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCStrings(t *testing.T) {
	t.Parallel()
	raw := [16]int8{'c', 'u', 'r', 'l'}
	if got, want := cString(raw[:]), "curl"; got != want {
		t.Errorf("cString(%v) = %q, want %q", raw, got, want)
	}
	full := [4]int8{'f', 'u', 'l', 'l'} // no terminator: the whole array is the string
	if got, want := cString(full[:]), "full"; got != want {
		t.Errorf("cString(%v) = %q, want %q", full, got, want)
	}
	path := [128]byte{'/', 'b', 'i', 'n', '/', 's', 'h'}
	if got, want := cBytes(path[:]), "/bin/sh"; got != want {
		t.Errorf("cBytes(%v) = %q, want %q", path[:8], got, want)
	}
}

func TestUserName(t *testing.T) {
	t.Parallel()
	r := testResolver(t)
	if got, want := r.userName(0), "root"; got != want {
		t.Errorf("userName(0) = %q, want %q", got, want)
	}
	// No passwd entry: the number stands in for the name.
	if got, want := r.userName(4294967294), "4294967294"; got != want {
		t.Errorf("userName(4294967294) = %q, want %q", got, want)
	}
	if got, want := r.userName(0), "root"; got != want {
		t.Errorf("userName(0) from the cache = %q, want %q", got, want)
	}
}

// testResolver is a resolver with a fixed clock and no kernel maps, enough
// for events whose program is this test process or no program at all.
func testResolver(t *testing.T) *resolver {
	t.Helper()
	r := newResolver(nil, &strings.Builder{})
	r.now = func() time.Time { return time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC) }
	r.reasons = map[uint32]string{2: "no_socket"}
	return r
}

func TestEnrich(t *testing.T) {
	t.Parallel()
	// Events of this process carry its pid and uid, the way the kernel side
	// fills them in; what they resolve to is read from /proc and the passwd
	// database, so the expectations hold whoever runs the tests.
	self, uid := uint32(os.Getpid()), uint32(os.Getuid())
	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current() error: %v", err)
	}
	comm, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatalf("read /proc/self/comm: %v", err)
	}
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatalf("read /proc/self/exe: %v", err)
	}
	at := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	// with fills in what every event of this process resolves to.
	with := func(c connection) connection {
		c.Time, c.PID, c.Comm, c.Exe, c.User = at, self, strings.TrimSpace(string(comm)), exe, me.Username
		return c
	}
	loopback := [16]uint8{127, 0, 0, 1}
	v6loop := [16]uint8{15: 1}

	tests := []struct {
		name string
		ev   monitorEvent
		want connection
	}{
		{
			name: "outgoing tcp",
			ev:   monitorEvent{Tgid: self, Uid: uid, Kind: kindOut, Family: unix.AF_INET, Proto: 6, Socktype: 1, Saddr: loopback, Sport: 40000, Daddr: loopback, Dport: 8000},
			want: with(connection{Kind: "out", Dir: "out", Proto: "tcp", Local: "127.0.0.1:40000", Remote: "127.0.0.1:8000"}),
		},
		{
			name: "door opens",
			ev:   monitorEvent{Tgid: self, Uid: uid, Kind: kindListen, Family: unix.AF_INET6, Proto: 6, Socktype: 1, Sport: 8000},
			want: with(connection{Kind: "listen", Dir: "in", Proto: "tcp", Local: "[::]:8000"}),
		},
		{
			name: "incoming drop without a program",
			ev:   monitorEvent{Kind: kindDropIn, Family: unix.AF_INET, Proto: 6, Saddr: loopback, Sport: 9, Daddr: loopback, Dport: 56640, Tcpflags: 0x02, Reason: 2, Ifindex: 1},
			want: connection{Time: at, Kind: "drop", Dir: "in", Proto: "tcp", Local: "127.0.0.1:9", Remote: "127.0.0.1:56640", Iface: "lo", Reason: "no_socket", Flags: "SYN"},
		},
		{
			name: "unknown drop reason",
			ev:   monitorEvent{Kind: kindDropOut, Family: unix.AF_INET6, Proto: 1, Saddr: v6loop, Daddr: v6loop, Reason: 999, Ifindex: 1, Repeats: 3},
			want: connection{Time: at, Kind: "drop", Dir: "out", Proto: "icmp", Local: "::1", Remote: "::1", Iface: "lo", Reason: "reason-999", Repeats: 3},
		},
		{
			name: "capture",
			ev:   monitorEvent{Tgid: self, Uid: uid, Kind: kindCapture, Family: unix.AF_PACKET, Socktype: 3, Ethertype: 3, Ifindex: 0},
			want: with(connection{Kind: "cap", Dir: "in", Proto: "packet", Iface: "any", Ethertype: "all"}),
		},
		{
			name: "frame sent through a packet socket",
			ev:   monitorEvent{Tgid: self, Uid: uid, Kind: kindOut, Family: unix.AF_PACKET, Socktype: 2, Ethertype: 0x0806, Ifindex: 1, Mac: [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
			want: with(connection{Kind: "out", Dir: "out", Proto: "packet", Iface: "lo", Ethertype: "arp", MAC: "ff:ff:ff:ff:ff:ff"}),
		},
		{
			name: "denied by a rule",
			ev:   monitorEvent{Tgid: self, Uid: uid, Kind: kindDenied, Family: unix.AF_INET, Proto: 6, Socktype: 1, Daddr: loopback, Dport: 23, Verdict: ruleDeny, Matched: 1},
			want: with(connection{Kind: "denied", Dir: "out", Proto: "tcp", Remote: "127.0.0.1:23", Reason: "denied by rule"}),
		},
		{
			name: "no rule, default applied",
			ev:   monitorEvent{Tgid: self, Uid: uid, Kind: kindAsk, Family: unix.AF_INET, Proto: 17, Socktype: 2, Daddr: loopback, Dport: 53, Verdict: ruleAllow},
			want: with(connection{Kind: "ask", Dir: "out", Proto: "udp", Remote: "127.0.0.1:53", Reason: "allowed by default, no rule"}),
		},
		{
			name: "unknown kind",
			ev:   monitorEvent{Kind: 200, Family: unix.AF_INET, Proto: 6, Socktype: 1},
			want: connection{Time: at, Kind: "?", Dir: "?", Proto: "tcp", Local: "0.0.0.0:0", Remote: "0.0.0.0:0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := testResolver(t).enrich(tt.ev); got != tt.want {
				t.Errorf("enrich(%+v) =\n  %+v\nwant\n  %+v", tt.ev, got, tt.want)
			}
		})
	}
}

func TestPrintText(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 1, 2, 16, 39, 8, 523_000_000, time.UTC)
	tests := []struct {
		name string
		c    connection
		want string
	}{
		{
			name: "tcp out",
			c:    connection{Time: at, Kind: "out", Dir: "out", Proto: "tcp", PID: 6588, Comm: "curl", User: "ubuntu", Local: "127.0.0.1:40598", Remote: "127.0.0.1:8000", Exe: "/usr/bin/curl"},
			want: "16:39:08.523  out       tcp        curl[6588]              ubuntu                127.0.0.1:40598 -> 127.0.0.1:8000  /usr/bin/curl\n",
		},
		{
			name: "snapshot with state",
			c:    connection{Time: at, Kind: "snap", Dir: "in", Proto: "tcp", PID: 2609, Comm: "sshd", User: "root", Local: "0.0.0.0:22", State: "LISTEN", Exe: "/usr/sbin/sshd"},
			want: "16:39:08.523  snap      tcp        sshd[2609]              root                  0.0.0.0:22 LISTEN  /usr/sbin/sshd\n",
		},
		{
			name: "drop without a program",
			c:    connection{Time: at, Kind: "drop", Dir: "in", Proto: "tcp", Local: "127.0.0.1:9", Remote: "127.0.0.1:42906", Iface: "lo", Reason: "no_socket", Flags: "SYN", Repeats: 1},
			want: "16:39:08.523  drop      tcp        -                       -                     127.0.0.1:9 <- 127.0.0.1:42906 SYN [x1]  no_socket (lo)\n",
		},
		{
			name: "capture",
			c:    connection{Time: at, Kind: "cap", Dir: "in", Proto: "packet", PID: 6693, Comm: "tcpdump", User: "root", Iface: "ens5", Ethertype: "all", Exe: "/usr/bin/tcpdump"},
			want: "16:39:08.523  cap       packet     tcpdump[6693]           root                  ens5 all  /usr/bin/tcpdump\n",
		},
		{
			name: "frame without a destination",
			c:    connection{Time: at, Kind: "out", Dir: "out", Proto: "packet", PID: 7001, Comm: "arping", User: "nobody", Iface: "ens5", Ethertype: "all", Exe: "/usr/bin/arping"},
			want: "16:39:08.523  out       packet     arping[7001]            nobody                ens5 -> ? all  /usr/bin/arping\n",
		},
		{
			name: "denied",
			c:    connection{Time: at, Kind: "denied", Dir: "out", Proto: "tcp", PID: 8120, Comm: "curl", User: "ubuntu", Remote: "23.215.0.136:443", Reason: "denied by rule", Exe: "/usr/bin/curl"},
			want: "16:39:08.523  denied    tcp        curl[8120]              ubuntu                -> 23.215.0.136:443  denied by rule  /usr/bin/curl\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var sb strings.Builder
			if err := printText(&sb, tt.c); err != nil {
				t.Fatalf("printText(%+v) error: %v", tt.c, err)
			}
			if got := sb.String(); got != tt.want {
				t.Errorf("printText(%+v) =\n%q\nwant\n%q", tt.c, got, tt.want)
			}
		})
	}
}
