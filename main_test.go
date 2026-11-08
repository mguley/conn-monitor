package main

import (
	"context"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestSplitList(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want []string
	}{
		{in: "", want: nil},
		{in: "a", want: []string{"a"}},
		{in: "a,b", want: []string{"a", "b"}},
		{in: " a , b ,, c,", want: []string{"a", "b", "c"}},
	}
	for _, tt := range tests {
		got := slices.Sorted(maps.Keys(splitList(tt.in)))
		if !slices.Equal(got, tt.want) {
			t.Errorf("splitList(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		args    []string
		want    options
		wantErr bool
	}{
		{name: "defaults", args: nil, want: options{ignoreDrops: "queue_purge", defaultAction: "allow"}},
		{
			name: "everything",
			args: []string{"-json", "-no-drops", "-no-snapshot", "-skip", "handle_exec", "-ignore-drops", "", "-block", "-rules", "r.txt", "-default", "deny", "-ask", "-cgroup", "/sys/fs/cgroup/unified"},
			want: options{asJSON: true, noDrops: true, noSnapshot: true, skip: "handle_exec", block: true, rulesFile: "r.txt", defaultAction: "deny", ask: true, cgroup: "/sys/fs/cgroup/unified"},
		},
		{name: "bad default", args: []string{"-default", "maybe"}, wantErr: true},
		{name: "ask without block", args: []string{"-ask"}, wantErr: true},
		{name: "rules without block", args: []string{"-rules", "r.txt"}, wantErr: true},
		{name: "unknown flag", args: []string{"-verbose"}, wantErr: true},
		{name: "stray argument", args: []string{"extra"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseFlags(tt.args, io.Discard)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseFlags(%q) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("parseFlags(%q) = %+v, want %+v", tt.args, got, tt.want)
			}
		})
	}
}

// TestHooksAttachable is the contract between the two sides: every program
// the kernel side defines has a section attach knows how to handle, and
// every hook name is unique. Loading the embedded object needs no root.
func TestHooksAttachable(t *testing.T) {
	t.Parallel()
	spec, err := loadMonitor()
	if err != nil {
		t.Fatalf("loadMonitor() error: %v", err)
	}
	if len(spec.Programs) == 0 {
		t.Fatal("loadMonitor() has no programs; was go generate run?")
	}
	for name, ps := range spec.Programs {
		kind, target, _ := strings.Cut(ps.SectionName, "/")
		switch kind {
		case "kprobe", "kretprobe", "cgroup":
			if target == "" {
				t.Errorf("program %s: section %q names no target", name, ps.SectionName)
			}
		case "tracepoint":
			if _, _, ok := strings.Cut(target, "/"); !ok {
				t.Errorf("program %s: section %q needs tracepoint/group/name", name, ps.SectionName)
			}
		default:
			t.Errorf("program %s: section %q is a kind attach doesn't know", name, ps.SectionName)
		}
	}
	for _, name := range []string{"events", "flows", "owners"} {
		if spec.Maps[name] == nil {
			t.Errorf("the compiled object has no %s map", name)
		}
	}
}

func TestRunList(t *testing.T) {
	t.Parallel()
	var out, errs strings.Builder
	if err := run(context.Background(), []string{"-list"}, strings.NewReader(""), &out, &errs); err != nil {
		t.Fatalf("run(-list) error: %v", err)
	}
	for _, want := range []string{"handle_kfree_skb             tracepoint/skb/kfree_skb\n", "block_connect4               cgroup/connect4\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("run(-list) output lacks %q:\n%s", want, out.String())
		}
	}
	if errs.Len() != 0 {
		t.Errorf("run(-list) wrote to stderr: %q", errs.String())
	}
}

func TestRunBadFlag(t *testing.T) {
	t.Parallel()
	if err := run(context.Background(), []string{"-default", "sometimes"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Error("run(-default sometimes) succeeded, want an error")
	}
}
