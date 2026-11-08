package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"os/user"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseHexAddrPort(t *testing.T) {
	t.Parallel()
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("test vectors assume a little-endian host")
	}
	tests := []struct {
		in   string
		want string
	}{
		{in: "0100007F:0035", want: "127.0.0.1:53"},
		{in: "00000000:0016", want: "0.0.0.0:22"},
		{in: "0F02A8C0:C8E2", want: "192.168.2.15:51426"},
		{in: "00000000000000000000000001000000:0035", want: "[::1]:53"},
		{in: "0000000000000000FFFF00000100007F:01BB", want: "127.0.0.1:443"}, // IPv4-mapped IPv6, unmapped on output
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := parseHexAddrPort(tt.in)
			if err != nil {
				t.Fatalf("parseHexAddrPort(%q) error: %v", tt.in, err)
			}
			if want := netip.MustParseAddrPort(tt.want); got != want {
				t.Errorf("parseHexAddrPort(%q) = %v, want %v", tt.in, got, want)
			}
		})
	}
	for _, in := range []string{"0100007F", "0100007:0035", "0100007F:ZZZZ", "0100007G:0035"} {
		if _, err := parseHexAddrPort(in); err == nil {
			t.Errorf("parseHexAddrPort(%q) succeeded, want an error", in)
		}
	}
}

func TestParseProcSockets(t *testing.T) {
	t.Parallel()
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("test vectors assume a little-endian host")
	}
	table := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 24135 1 0000000000000000 100 0 0 10 5
   1: FD171FAC:0016 3156D668:CF86 01 00000000:00000000 02:000A2F52 00000000     0        0 31977 4 0000000000000000 20 4 30 10 -1
   2: 0100007F:1F90 0100007F:9E86 06 00000000:00000000 03:000016E9 00000000     0        0 0 3 0000000000000000
`
	got, err := parseProcSockets(table, "tcp", "test")
	if err != nil {
		t.Fatalf("parseProcSockets() error: %v", err)
	}
	want := []procSocket{
		{proto: "tcp", local: netip.MustParseAddrPort("127.0.0.53:53"), remote: netip.MustParseAddrPort("0.0.0.0:0"), state: "LISTEN", uid: 991, inode: 24135},
		{proto: "tcp", local: netip.MustParseAddrPort("172.31.23.253:22"), remote: netip.MustParseAddrPort("104.214.86.49:53126"), state: "ESTABLISHED", uid: 0, inode: 31977},
		{proto: "tcp", local: netip.MustParseAddrPort("127.0.0.1:8080"), remote: netip.MustParseAddrPort("127.0.0.1:40582"), state: "TIME_WAIT", uid: 0, inode: 0},
	}
	if len(got) != len(want) {
		t.Fatalf("parseProcSockets() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parseProcSockets()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	udp, err := parseProcSockets("header\n   0: 0100007F:0143 00000000:0000 07 00000000:00000000 00:00000000 00000000   114        0 20330 2 0000000000000000 0\n", "udp", "test")
	if err != nil {
		t.Fatalf("parseProcSockets(udp) error: %v", err)
	}
	if len(udp) != 1 || udp[0].state != "UNCONN" {
		t.Errorf("parseProcSockets(udp) = %+v, want one UNCONN socket", udp)
	}

	if _, err := parseProcSockets("header\n   0: 0100007F:0143 00000000:0000 07 00000000:00000000 00:00000000 00000000   abc        0 20330\n", "udp", "test"); err == nil {
		t.Error("parseProcSockets(bad uid) succeeded, want an error")
	}
}

func TestSnapshotSeesOwnListener(t *testing.T) {
	// Not parallel: it opens a listening socket and reads /proc. Other
	// users' processes need root to be read; our own is always readable.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	r := newResolver(nil, io.Discard)
	r.now = func() time.Time { return time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC) }
	conns, err := snapshot(r)
	if err != nil {
		t.Fatalf("snapshot() error: %v", err)
	}
	self := uint32(os.Getpid())
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	comm, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal(err)
	}
	want := connection{
		Time: r.now(), Kind: "snap", Dir: "in", Proto: "tcp", PID: self,
		Comm: strings.TrimSpace(string(comm)), Exe: exe, User: me.Username,
		Local: ln.Addr().String(), State: "LISTEN",
	}
	if !slices.Contains(conns, want) {
		t.Errorf("snapshot() lacks this process's listener %+v; got %d connections:\n%+v", want, len(conns), conns)
	}
}
