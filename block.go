// The terminal side of the block module in bpf/block.bpf.h: rules are read
// from a file and written into the kernel's rules map, the default policy
// into its settings map. With -ask, an attempt no rule covered becomes a
// question, and the answer a rule. The kernel does all the deciding.
//
// A rule names a program by path; the kernel knows a program by the file it
// runs, as device and inode numbers. The translation happens here, when a
// rule is written, so every path that leads to the same file is the same
// program: /usr/bin/python3 and /usr/bin/python3.14, /bin/bash and
// /usr/bin/bash.
package main

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Rule actions, matching RULE_* in bpf/block.bpf.h.
const (
	ruleAllow = 1
	ruleDeny  = 2
)

// rule is one line of the rules file: an action, a program (its absolute
// path, or * for any), and a destination (*, address, address:port, :port).
type rule struct {
	action uint8
	exe    string
	addr   netip.Addr // the zero Addr means any address
	port   uint16     // 0 means any port
}

// parseRule reads one line of the rules file. Blank lines and comments give
// ok == false without an error.
func parseRule(line string) (r rule, ok bool, err error) {
	line, _, _ = strings.Cut(line, "#")
	f := strings.Fields(line)

	if len(f) == 0 {
		return rule{}, false, nil
	}
	if len(f) != 3 {
		return rule{}, false, fmt.Errorf("want: action program destination, got %q", strings.TrimSpace(line))
	}

	switch f[0] {
	case "allow":
		r.action = ruleAllow
	case "deny":
		r.action = ruleDeny
	default:
		return rule{}, false, fmt.Errorf("action must be allow or deny, got %q", f[0])
	}

	r.exe = f[1]
	if r.exe != "*" && !strings.HasPrefix(r.exe, "/") {
		return rule{}, false, fmt.Errorf("program must be an absolute path or *, got %q", r.exe)
	}

	if err := parseDest(f[2], &r); err != nil {
		return rule{}, false, err
	}

	return r, true, nil
}

// parseDest fills a rule's address and port from a destination: *, an
// address, address:port ([v6]:port for IPv6), or :port. Addresses are tried
// before ports because an IPv6 address can start with a colon too (::1).
func parseDest(s string, r *rule) error {
	if s == "*" {
		return nil
	}

	if ap, err := netip.ParseAddrPort(s); err == nil {
		r.addr, r.port = ap.Addr().Unmap(), ap.Port()
		return nil
	}

	if a, err := netip.ParseAddr(s); err == nil {
		r.addr = a.Unmap()
		return nil
	}

	if port, ok := strings.CutPrefix(s, ":"); ok {
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return fmt.Errorf("port %q: %w", s, err)
		}

		r.port = uint16(p)
		return nil
	}

	return fmt.Errorf("destination %q: want *, address, address:port or :port", s)
}

// destString is the inverse of parseDest.
func destString(r rule) string {
	switch {
	case !r.addr.IsValid() && r.port == 0:
		return "*"
	case !r.addr.IsValid():
		return ":" + strconv.Itoa(int(r.port))
	case r.port == 0:
		return r.addr.String()
	}

	return netip.AddrPortFrom(r.addr, r.port).String()
}

// actionName names an action.
func actionName(a uint8) string {
	if a == ruleDeny {
		return "deny"
	}
	return "allow"
}

// ruleText renders a rule the way the rules file spells it.
func ruleText(r rule) string {
	return actionName(r.action) + " " + r.exe + " " + destString(r)
}

// ruleKey lays a rule out the way bpf/block.bpf.h expects it: the program
// as the identity of its file, the destination as address family, address
// and port, with zeros for "any".
func ruleKey(r rule) (monitorRuleKey, error) {
	var k monitorRuleKey
	if r.exe != "*" {
		id, err := identify(r.exe)
		if err != nil {
			return monitorRuleKey{}, err
		}
		k.Dev, k.Ino = id.dev, id.ino
	}

	k.Dport = r.port

	switch {
	case r.addr.Is4():
		k.Family = unix.AF_INET
		copy(k.Daddr[:], r.addr.AsSlice())
	case r.addr.Is6():
		k.Family = unix.AF_INET6
		copy(k.Daddr[:], r.addr.AsSlice())
	}

	return k, nil
}

// ruleValue lays out the action and the program's path as written, which
// the kernel keeps so the rule can be printed back. The path is cut at 127
// bytes to leave the terminating NUL.
func ruleValue(r rule) monitorRule {
	v := monitorRule{Action: r.action}

	for i := range min(len(r.exe), len(v.Exe)-1) {
		v.Exe[i] = int8(r.exe[i])
	}

	return v
}

// keyRule is the inverse of ruleKey and ruleValue, for printing what the
// kernel holds.
func keyRule(k monitorRuleKey, v monitorRule) rule {
	r := rule{action: v.Action, exe: cString(v.Exe[:]), port: k.Dport}

	switch k.Family {
	case unix.AF_INET:
		r.addr = netip.AddrFrom4([4]byte(k.Daddr[:4]))
	case unix.AF_INET6:
		r.addr = netip.AddrFrom16(k.Daddr)
	}

	return r
}

// fileID identifies a file the way the kernel does: the device of the file
// system it lives on and its inode number. It is what bpf/block.bpf.h reads
// from the calling process's executable.
type fileID struct {
	dev uint32 // the kernel's encoding: major << 20 | minor
	ino uint64
}

// identify returns the identity of the file at path, following symlinks. The
// device number comes from the mount table rather than from stat, because
// stat reports a per-subvolume number on btrfs while the kernel side sees
// the file system's own; the mount table has that one, found by the mount
// ID statx reports for the file.
func identify(path string) (fileID, error) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_INO|unix.STATX_MNT_ID, &st); err != nil {
		return fileID{}, fmt.Errorf("stat %s: %w", path, err)
	}

	id := fileID{dev: st.Dev_major<<20 | st.Dev_minor, ino: st.Ino}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return id, nil // a kernel too old to say which mount; stat's number will do
	}

	mounts, err := readMounts()
	if err != nil {
		return fileID{}, err
	}

	for _, m := range mounts {
		if m.id == st.Mnt_id {
			id.dev = m.dev
			break
		}
	}

	return id, nil
}

// mount is one line of /proc/self/mountinfo.
type mount struct {
	id     uint64
	dev    uint32 // the superblock's device, in the kernel's encoding
	point  string
	fstype string
}

// readMounts parses /proc/self/mountinfo. A line reads
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//
// mount ID, parent ID, major:minor of the file system, root, mount point,
// options, optional fields up to "-", then the file system type.
func readMounts() ([]mount, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	return parseMounts(string(data)), nil
}

// parseMounts reads the text of a mountinfo table, skipping lines it can't
// make sense of.
func parseMounts(table string) []mount {
	var mounts []mount

	for line := range strings.Lines(table) {
		before, after, ok := strings.Cut(line, " - ")
		f := strings.Fields(before)

		if !ok || len(f) < 5 {
			continue
		}

		id, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}

		major, minor, ok := strings.Cut(f[2], ":")
		if !ok {
			continue
		}

		ma, err1 := strconv.ParseUint(major, 10, 12)
		mi, err2 := strconv.ParseUint(minor, 10, 20)
		if err1 != nil || err2 != nil {
			continue
		}

		fstype, _, _ := strings.Cut(after, " ")
		mounts = append(mounts, mount{id: id, dev: uint32(ma<<20 | mi), point: unescapeMount(f[4]), fstype: fstype})
	}

	return mounts
}

// unescapeMount decodes the octal escapes mountinfo uses for spaces and the
// like in mount points (\040 is a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}

	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if c, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				sb.WriteByte(byte(c))
				i += 3
				continue
			}
		}
		sb.WriteByte(s[i])
	}

	return sb.String()
}

// cgroup2Root finds where the cgroup v2 hierarchy is mounted: /sys/fs/cgroup
// on any current Ubuntu, /sys/fs/cgroup/unified on a system still booting in
// hybrid mode. The block module's programs attach there, so they see every
// process.
func cgroup2Root() (string, error) {
	mounts, err := readMounts()
	if err != nil {
		return "", err
	}

	for _, m := range mounts {
		if m.fstype == "cgroup2" {
			return m.point, nil
		}
	}

	return "", errors.New("no cgroup2 mount in /proc/self/mountinfo")
}

// addRule writes a rule into the kernel.
func addRule(rules *ebpf.Map, r rule) error {
	k, err := ruleKey(r)
	if err != nil {
		return err
	}

	return rules.Put(k, ruleValue(r))
}

// parseRules reads a whole rules file, reporting the line of the first
// mistake.
func parseRules(text string) ([]rule, error) {
	var rules []rule

	lineNo := 0
	for line := range strings.Lines(text) {
		lineNo++
		r, ok, err := parseRule(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if ok {
			rules = append(rules, r)
		}
	}

	return rules, nil
}

// loadRules reads a rules file into the kernel and returns how many rules
// it loaded.
func loadRules(path string, rules *ebpf.Map) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	parsed, err := parseRules(string(data))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}

	for i, r := range parsed {
		if err := addRule(rules, r); err != nil {
			return i, fmt.Errorf("%s: %s: %w", path, ruleText(r), err)
		}
	}

	return len(parsed), nil
}

// configureBlocking writes the default policy and the rules into the
// kernel. It runs before the hooks are attached, so there is no moment with
// the wrong policy.
func configureBlocking(coll *ebpf.Collection, defaultAction, rulesFile string, stderr io.Writer) error {
	rules, settings := coll.Maps["rules"], coll.Maps["settings"]
	if rules == nil || settings == nil {
		return errors.New("-block needs the block module: bpf/monitor.bpf.c must include block.bpf.h")
	}

	action := uint8(ruleAllow)
	if defaultAction == "deny" {
		action = ruleDeny
	}

	if err := settings.Put(uint32(0), monitorPolicy{DefaultAction: action}); err != nil {
		return fmt.Errorf("write settings: %w", err)
	}

	n := 0
	if rulesFile != "" {
		var err error
		if n, err = loadRules(rulesFile, rules); err != nil {
			return err
		}
	}

	fmt.Fprintf(stderr, "conn-monitor: block module armed: default %s, %d rules\n", defaultAction, n)
	return nil
}

// askPrompt prints the question for an attempt no rule covered. The answer
// arrives through readLines and applyAnswer turns it into a rule.
func askPrompt(w io.Writer, c connection) {
	exe := c.Exe
	if exe == "" {
		exe = "(unknown program)"
	}

	fmt.Fprintf(w, "? %s -> %s was %s. Rule for %s: [a]llow / [d]eny this destination, [A]llow / [D]eny everywhere, Enter to skip: ",
		c.Comm, c.Remote, c.Reason, exe)
}

// answerRule turns a typed answer into the rule it asks for, for the
// attempt it answers. ok is false when the answer was to skip.
func answerRule(answer string, c connection) (r rule, ok bool, err error) {
	r = rule{exe: c.Exe}
	everywhere := false

	switch strings.TrimSpace(answer) {
	case "":
		return rule{}, false, nil
	case "a":
		r.action = ruleAllow
	case "d":
		r.action = ruleDeny
	case "A":
		r.action, everywhere = ruleAllow, true
	case "D":
		r.action, everywhere = ruleDeny, true
	default:
		return rule{}, false, fmt.Errorf("answer %q not understood; a, d, A, D or Enter", answer)
	}

	if r.exe == "" {
		return rule{}, false, errors.New("the program's path is unknown, no rule written")
	}
	if !everywhere {
		if err := parseDest(c.Remote, &r); err != nil {
			return rule{}, false, err
		}
	}

	return r, true, nil
}

// applyAnswer turns a typed answer into a rule for the attempt it answers,
// writes it into the kernel, and appends it to the rules file if there is
// one. It returns the rule's text, or "" when the answer was to skip.
func applyAnswer(answer string, c connection, rules *ebpf.Map, file string) (string, error) {
	r, ok, err := answerRule(answer, c)
	if err != nil || !ok {
		return "", err
	}

	if err := addRule(rules, r); err != nil {
		return "", err
	}

	text := ruleText(r)
	if file == "" {
		return text, nil
	}

	if err := appendLine(file, text); err != nil {
		return text, fmt.Errorf("rule added in the kernel but not saved: %w", err)
	}

	return text, nil
}

// appendLine adds one line to the end of a file, creating it if needed.
func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintln(f, line); err != nil {
		_ = f.Close() // the write error is the one worth reporting
		return err
	}

	return f.Close()
}

// printRules lists the rules in the kernel with how often each decided.
func printRules(w io.Writer, rules *ebpf.Map) {
	if rules == nil {
		return
	}

	var k monitorRuleKey
	var v monitorRule
	var lines []string
	it := rules.Iterate()
	for it.Next(&k, &v) {
		lines = append(lines, fmt.Sprintf("  x%-7d %s", v.Hits, ruleText(keyRule(k, v))))
	}

	if err := it.Err(); err != nil {
		fmt.Fprintln(w, "conn-monitor: reading rules:", err)
	}
	if len(lines) == 0 {
		return
	}

	slices.Sort(lines)
	fmt.Fprintln(w, "conn-monitor: rules and how often each decided:")

	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}
