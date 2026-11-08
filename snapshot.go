// The picture of the sockets that already exist when conn-monitor starts, read
// from /proc the way netstat does. This is the first tool from this project,
// kept as a one-time snapshot: events only ever report what changes, and
// this is what they change from.
package main

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// tcpStates names the hexadecimal state column of /proc/net/tcp
// (include/net/tcp_states.h in the kernel). UDP reuses 07 for "not connected".
var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
	"0D": "BOUND_INACTIVE",
}

// procSocket is one row of a /proc/net socket table.
type procSocket struct {
	proto  string // tcp or udp
	local  netip.AddrPort
	remote netip.AddrPort
	state  string
	uid    uint32
	inode  uint64 // 0 once no process holds the socket anymore (TIME_WAIT etc.)
}

// procOwner is the process holding a socket's file descriptor.
type procOwner struct {
	pid  int
	comm string
}

// snapshot returns every TCP and UDP socket a process currently holds, as
// connections of kind "snap", sorted by program.
func snapshot(r *resolver) ([]connection, error) {
	var socks []procSocket
	for _, t := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp"},
	} {
		s, err := readProcSockets(t.path, t.proto)
		if errors.Is(err, fs.ErrNotExist) {
			continue // IPv6 is disabled on this machine
		}
		if err != nil {
			return nil, err
		}
		socks = append(socks, s...)
	}

	// The kernel doesn't record who opened a connection; if we listen on its
	// local port, the peer connected to us, otherwise we connected to the peer.
	listening := make(map[uint16]bool)
	for _, s := range socks {
		if s.state == "LISTEN" {
			listening[s.local.Port()] = true
		}
	}
	owners, err := socketOwners()
	if err != nil {
		return nil, err
	}

	now := r.now()
	var conns []connection

	for _, s := range socks {
		o, ok := owners[s.inode]
		if !ok {
			continue // nobody holds it anymore (TIME_WAIT and the like)
		}
		c := connection{
			Time:  now,
			Kind:  "snap",
			Dir:   "out",
			Proto: s.proto,
			PID:   uint32(o.pid),
			Comm:  o.comm,
			Exe:   r.exePath(uint32(o.pid)),
			User:  r.userName(s.uid),
			Local: s.local.String(),
			State: s.state,
		}

		switch {
		case s.state == "LISTEN" || s.remote.Port() == 0:
			c.Dir = "in" // a door, or an unconnected datagram socket
		case listening[s.local.Port()]:
			c.Dir = "in"
			c.Remote = s.remote.String()
		default:
			c.Remote = s.remote.String()
		}

		conns = append(conns, c)
	}

	slices.SortFunc(conns, func(a, b connection) int {
		return cmp.Or(cmp.Compare(a.Comm, b.Comm), cmp.Compare(a.PID, b.PID), cmp.Compare(a.Local, b.Local))
	})

	return conns, nil
}

// readProcSockets parses one /proc/net socket table. A row looks like
//
//	sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
//	0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000 991 0 24135 ...
func readProcSockets(path, proto string) ([]procSocket, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseProcSockets(string(data), proto, path)
}

// parseProcSockets turns the text of a socket table into rows. name is only
// used in error messages.
func parseProcSockets(table, proto, name string) ([]procSocket, error) {
	var socks []procSocket
	header := true

	for line := range strings.Lines(table) {
		if header {
			header = false
			continue
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			continue // trailing blank line
		}

		local, err := parseHexAddrPort(f[1])
		if err != nil {
			return nil, fmt.Errorf("%s: local address %q: %w", name, f[1], err)
		}

		remote, err := parseHexAddrPort(f[2])
		if err != nil {
			return nil, fmt.Errorf("%s: remote address %q: %w", name, f[2], err)
		}

		uid, err := strconv.ParseUint(f[7], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%s: uid %q: %w", name, f[7], err)
		}

		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: inode %q: %w", name, f[9], err)
		}

		state, ok := tcpStates[f[3]]
		if !ok {
			state = f[3]
		}

		if proto == "udp" && f[3] == "07" {
			state = "UNCONN"
		}

		socks = append(socks, procSocket{
			proto: proto, local: local, remote: remote, state: state, uid: uint32(uid), inode: inode,
		})
	}

	return socks, nil
}

// parseHexAddrPort decodes the kernel's "HEXADDR:HEXPORT" notation. The
// address is printed as 32-bit words in host byte order, which is why
// 127.0.0.1 appears as 0100007F on x86 and arm64; binary.NativeEndian
// reverses that correctly on any architecture. The port is plain hex.
func parseHexAddrPort(s string) (netip.AddrPort, error) {
	hexAddr, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, errors.New("missing ':'")
	}

	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(hexAddr) != 8 && len(hexAddr) != 32 { // IPv4 or IPv6
		return netip.AddrPort{}, fmt.Errorf("address %q has %d hex digits", hexAddr, len(hexAddr))
	}

	raw := make([]byte, len(hexAddr)/2)
	for i := range len(raw) / 4 {
		word, err := strconv.ParseUint(hexAddr[8*i:8*i+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, err
		}
		binary.NativeEndian.PutUint32(raw[4*i:], uint32(word))
	}

	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", hexAddr)
	}

	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}

// socketOwners maps socket inodes to the processes holding them, by reading
// every /proc/<pid>/fd. As root that is every process.
func socketOwners() (map[uint64]procOwner, error) {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	owners := make(map[uint64]procOwner)
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue // /proc/net, /proc/sys, ...: not a process
		}

		dir := filepath.Join("/proc", p.Name())
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue // it exited between the two reads
		}

		o := procOwner{pid: pid, comm: "?"}
		if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
			o.comm = strings.TrimSpace(string(b))
		}

		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil {
				continue // closed between ReadDir and Readlink
			}

			num, ok := strings.CutPrefix(target, "socket:[")
			if !ok {
				continue // a file, pipe, anon inode, ...
			}

			inode, err := strconv.ParseUint(strings.TrimSuffix(num, "]"), 10, 64)
			if err != nil {
				continue
			}

			owners[inode] = o
		}
	}

	return owners, nil
}
