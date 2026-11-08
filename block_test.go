package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseRule(t *testing.T) {
	t.Parallel()
	tests := []struct {
		line    string
		want    string // ruleText of the parsed rule; "" for a skipped line
		wantErr bool
	}{
		{line: "deny /usr/bin/curl *", want: "deny /usr/bin/curl *"},
		{line: "allow /usr/bin/curl 93.184.216.34:443", want: "allow /usr/bin/curl 93.184.216.34:443"},
		{line: "deny * :23", want: "deny * :23"},
		{line: "allow * 2606:4700::1111", want: "allow * 2606:4700::1111"},
		{line: "allow * [2606:4700::1111]:53", want: "allow * [2606:4700::1111]:53"},
		{line: "allow /usr/bin/curl ::ffff:10.0.0.5", want: "allow /usr/bin/curl 10.0.0.5"},
		{line: "allow /usr/bin/curl ::1", want: "allow /usr/bin/curl ::1"},
		{line: "allow /usr/bin/curl [::1]:53", want: "allow /usr/bin/curl [::1]:53"},
		{line: "  deny   /usr/bin/curl   *   # trailing comment", want: "deny /usr/bin/curl *"},
		{line: "  # a comment"},
		{line: ""},
		{line: "deny /usr/bin/curl * extra", wantErr: true},
		{line: "maybe /usr/bin/curl *", wantErr: true},
		{line: "deny curl *", wantErr: true},
		{line: "deny /usr/bin/curl nowhere", wantErr: true},
		{line: "deny /usr/bin/curl :99999", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()
			r, ok, err := parseRule(tt.line)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseRule(%q) error = %v, wantErr %v", tt.line, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if ok != (tt.want != "") {
				t.Fatalf("parseRule(%q) ok = %v, want %v", tt.line, ok, tt.want != "")
			}
			if got := ruleText(r); ok && got != tt.want {
				t.Errorf("ruleText(parseRule(%q)) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestRuleKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	exe := filepath.Join(dir, "tool")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	id, err := identify(exe)
	if err != nil {
		t.Fatalf("identify(%q) error: %v", exe, err)
	}

	tests := []struct {
		name string
		line string
		want monitorRuleKey
	}{
		{
			name: "program, address and port",
			line: "deny " + exe + " 93.184.216.34:443",
			want: monitorRuleKey{Dev: id.dev, Ino: id.ino, Family: unix.AF_INET, Dport: 443, Daddr: [16]uint8{93, 184, 216, 34}},
		},
		{
			name: "program and ipv6 address",
			line: "allow " + exe + " ::1",
			want: monitorRuleKey{Dev: id.dev, Ino: id.ino, Family: unix.AF_INET6, Daddr: [16]uint8{15: 1}},
		},
		{
			name: "any program, port only",
			line: "deny * :23",
			want: monitorRuleKey{Dport: 23},
		},
		{
			name: "anything",
			line: "allow * *",
			want: monitorRuleKey{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _, err := parseRule(tt.line)
			if err != nil {
				t.Fatalf("parseRule(%q) error: %v", tt.line, err)
			}
			got, err := ruleKey(r)
			if err != nil {
				t.Fatalf("ruleKey(%q) error: %v", tt.line, err)
			}
			if got != tt.want {
				t.Errorf("ruleKey(%q) = %+v, want %+v", tt.line, got, tt.want)
			}
			// What the kernel holds prints back as the rule that was written.
			if back := ruleText(keyRule(got, ruleValue(r))); back != ruleText(r) {
				t.Errorf("keyRule(ruleKey(%q)) = %q, want %q", tt.line, back, ruleText(r))
			}
		})
	}
}

func TestParseRules(t *testing.T) {
	t.Parallel()
	rules, err := parseRules("# comment\n\ndeny /usr/bin/curl *\nallow * :53 # dns\n")
	if err != nil {
		t.Fatalf("parseRules() error: %v", err)
	}
	var got []string
	for _, r := range rules {
		got = append(got, ruleText(r))
	}
	if want := []string{"deny /usr/bin/curl *", "allow * :53"}; !slices.Equal(got, want) {
		t.Errorf("parseRules() = %q, want %q", got, want)
	}
	_, err = parseRules("deny /usr/bin/curl *\n\nmaybe /usr/bin/curl *\n")
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("parseRules(bad third line) error = %v, want one naming line 3", err)
	}
}

func TestRuleKeyMissingProgram(t *testing.T) {
	t.Parallel()
	r, _, err := parseRule("deny /no/such/program *")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ruleKey(r); err == nil {
		t.Error("ruleKey(missing program) succeeded, want an error")
	}
}

func TestRuleValueCutsLongPaths(t *testing.T) {
	t.Parallel()
	long := "/" + strings.Repeat("a", 200)
	v := ruleValue(rule{action: ruleAllow, exe: long})
	if v.Exe[len(v.Exe)-1] != 0 {
		t.Errorf("ruleValue(%d-byte path) has no terminating NUL", len(long))
	}
	if got, want := len(cString(v.Exe[:])), len(v.Exe)-1; got != want {
		t.Errorf("ruleValue(%d-byte path) kept %d bytes, want %d", len(long), got, want)
	}
}

// TestIdentify checks that every path to a file is the same program, which
// is the point of identifying programs by file rather than by path.
func TestIdentify(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	singlePath := filepath.Join(dir, "python3.14")
	if err := os.WriteFile(singlePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "python3")
	if err := os.Symlink("python3.14", link); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	want, err := identify(singlePath)
	if err != nil {
		t.Fatalf("identify(%q) error: %v", singlePath, err)
	}
	if want.ino == 0 {
		t.Fatalf("identify(%q) = %+v, want a non-zero inode", singlePath, want)
	}
	for _, path := range []string{link, filepath.Join(dir, "..", filepath.Base(dir), "python3.14")} {
		got, err := identify(path)
		if err != nil {
			t.Fatalf("identify(%q) error: %v", path, err)
		}
		if got != want {
			t.Errorf("identify(%q) = %+v, want %+v (the same file as %q)", path, got, want, singlePath)
		}
	}
	if got, err := identify(other); err != nil {
		t.Fatalf("identify(%q) error: %v", other, err)
	} else if got == want {
		t.Errorf("identify(%q) = %+v, the same as %q", other, got, singlePath)
	}
	if _, err := identify(filepath.Join(dir, "missing")); err == nil {
		t.Error("identify(missing) succeeded, want an error")
	}
}

func TestParseMounts(t *testing.T) {
	t.Parallel()
	table := `23 28 0:22 / /proc rw,relatime - proc proc rw
28 1 252:1 / / rw,relatime - ext4 /dev/vda1 rw
36 28 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
40 28 0:35 / /mnt/with\040space rw,relatime master:1 - tmpfs tmpfs rw
garbage line
41 28 nodev / /bad rw - weird x
`
	got := parseMounts(table)
	want := []mount{
		{id: 23, dev: 0<<20 | 22, point: "/proc", fstype: "proc"},
		{id: 28, dev: 252<<20 | 1, point: "/", fstype: "ext4"},
		{id: 36, dev: 0<<20 | 30, point: "/sys/fs/cgroup", fstype: "cgroup2"},
		{id: 40, dev: 0<<20 | 35, point: "/mnt/with space", fstype: "tmpfs"},
	}
	if len(got) != len(want) {
		t.Fatalf("parseMounts() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parseMounts()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestUnescapeMount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{in: "/plain", want: "/plain"},
		{in: `/with\040space`, want: "/with space"},
		{in: `/tab\011and\134backslash`, want: "/tab\tand\\backslash"},
		{in: `/cut\04`, want: `/cut\04`},
		{in: `/not\zzz`, want: `/not\zzz`},
	}
	for _, tt := range tests {
		if got := unescapeMount(tt.in); got != tt.want {
			t.Errorf("unescapeMount(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCgroup2Root(t *testing.T) {
	t.Parallel()
	root, err := cgroup2Root()
	if err != nil {
		t.Skipf("no cgroup v2 on this machine: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		t.Errorf("cgroup2Root() = %q, which has no cgroup.controllers: %v", root, err)
	}
}

func TestAnswerRule(t *testing.T) {
	t.Parallel()
	attempt := connection{Comm: "python3", Exe: "/usr/bin/python3.14", Remote: "23.215.0.136:443"}
	tests := []struct {
		name    string
		answer  string
		c       connection
		want    string // ruleText; "" when skipped
		wantErr bool
	}{
		{name: "allow destination", answer: "a", c: attempt, want: "allow /usr/bin/python3.14 23.215.0.136:443"},
		{name: "deny destination", answer: "d\n", c: attempt, want: "deny /usr/bin/python3.14 23.215.0.136:443"},
		{name: "allow everywhere", answer: "A", c: attempt, want: "allow /usr/bin/python3.14 *"},
		{name: "deny everywhere", answer: " D ", c: attempt, want: "deny /usr/bin/python3.14 *"},
		{name: "ipv6 destination", answer: "d", c: connection{Exe: "/usr/bin/curl", Remote: "[2606:4700::1111]:53"}, want: "deny /usr/bin/curl [2606:4700::1111]:53"},
		{name: "skip", answer: "", c: attempt},
		{name: "not understood", answer: "x", c: attempt, wantErr: true},
		{name: "unknown program", answer: "a", c: connection{Remote: "1.2.3.4:5"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, ok, err := answerRule(tt.answer, tt.c)
			if (err != nil) != tt.wantErr {
				t.Fatalf("answerRule(%q) error = %v, wantErr %v", tt.answer, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if ok != (tt.want != "") {
				t.Fatalf("answerRule(%q) ok = %v, want %v", tt.answer, ok, tt.want != "")
			}
			if got := ruleText(r); ok && got != tt.want {
				t.Errorf("answerRule(%q) = %q, want %q", tt.answer, got, tt.want)
			}
		})
	}
}

func TestAppendLine(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rules.txt")
	for _, line := range []string{"deny /usr/bin/curl *", "allow * :53"} {
		if err := appendLine(path, line); err != nil {
			t.Fatalf("appendLine(%q) error: %v", line, err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "deny /usr/bin/curl *\nallow * :53\n"; string(got) != want {
		t.Errorf("rules file = %q, want %q", got, want)
	}
}
