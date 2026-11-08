// Command conn-monitor prints every new network conversation on this machine the
// moment it starts, together with the program behind it: TCP connections
// opened or accepted, ports a program starts or stops listening on, datagram
// flows (UDP, ICMP, raw, SCTP) sent or received, packet sockets opened below
// IP (ARP, DHCP, sniffers), and packets the kernel threw away, with the
// reason. It starts with a snapshot of the sockets that already exist. With
// -block it also enforces rules: which program may open which connection.
//
// The kernel side lives in bpf/, one module per responsibility, compiled by
// go generate into one object that this binary embeds. This file loads that
// object, attaches every program in it where its section name says, and
// runs the loop that prints the events coming back. Turning raw events into
// words is in event.go, the rules in block.go, the snapshot in snapshot.go.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// native compiles for the machine running go generate (x86 or arm64), which
// is what the kprobe argument macros need to know.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native -type event monitor bpf/monitor.bpf.c

// options are the command-line flags.
type options struct {
	asJSON        bool
	list          bool
	skip          string
	noDrops       bool
	noSnapshot    bool
	ignoreDrops   string
	block         bool
	rulesFile     string
	defaultAction string
	ask           bool
	cgroup        string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, unix.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "conn-monitor:", err)
		os.Exit(1)
	}
}

// run is the whole program: it loads the compiled object, arms the hooks,
// prints the snapshot and then every event until ctx is done. Notes that are
// not events go to stderr; events go to stdout.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}

	// The compiled object: every program and map the modules in bpf/ define.
	spec, err := loadMonitor()
	if err != nil {
		return err
	}
	if opts.list {
		listHooks(stdout, spec)
		return nil
	}

	// BPF maps count against the locked-memory limit on older kernels; lift it.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	// Load the programs and maps into the kernel. The verifier checks every
	// program here, so a rejected program fails at this step.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		if ve, ok := errors.AsType[*ebpf.VerifierError](err); ok {
			return fmt.Errorf("the kernel's verifier rejected a program:\n%+v", ve)
		}
		return fmt.Errorf("load BPF objects (run as root?): %w", err)
	}
	defer coll.Close()

	events := coll.Maps["events"]
	if events == nil {
		return errors.New("the compiled object has no events map: bpf/monitor.bpf.c must include common.bpf.h")
	}

	skipped := make(map[string]string) // program name -> note to print, "" for silence
	for name := range splitList(opts.skip) {
		skipped[name] = "skipped as asked"
	}
	if opts.noDrops {
		skipped["handle_kfree_skb"] = "skipped as asked"
	}

	// Blocking is opt-in. Without -block the block module's programs stay
	// loaded but unattached; with it, the policy and rules go into the maps
	// before the hooks are armed, so there is no moment with the wrong policy.
	cgroup := opts.cgroup
	if opts.block {
		if cgroup == "" {
			if cgroup, err = cgroup2Root(); err != nil {
				return fmt.Errorf("-block needs the cgroup v2 hierarchy: %w", err)
			}
		}
		if err := configureBlocking(coll, opts.defaultAction, opts.rulesFile, stderr); err != nil {
			return err
		}
	} else {
		n := 0
		for name, ps := range spec.Programs {
			if strings.HasPrefix(ps.SectionName, "cgroup/") {
				skipped[name] = ""
				n++
			}
		}
		if n > 0 {
			fmt.Fprintf(stderr, "conn-monitor: %d block hooks present but not armed; start with -block to enforce rules\n", n)
		}
	}

	links, err := attachAll(spec, coll, skipped, cgroup, stderr)
	defer func() {
		for _, l := range links {
			_ = l.Close() // the kernel drops the hook with the process anyway
		}
	}()
	if err != nil {
		return err
	}

	rd, err := ringbuf.NewReader(events)
	if err != nil {
		return fmt.Errorf("open ring buffer: %w", err)
	}
	defer rd.Close()

	m := &monitor{
		r:         newResolver(coll.Maps["exes"], stderr),
		ignored:   splitList(opts.ignoreDrops),
		rules:     coll.Maps["rules"],
		rulesFile: opts.rulesFile,
		stdout:    stdout,
		stderr:    stderr,
	}
	if opts.asJSON {
		m.enc = json.NewEncoder(stdout)
	}

	// The hooks are attached, so from here on nothing is missed; now the
	// picture of what already exists, which events only ever change.
	if !opts.noSnapshot {
		conns, err := snapshot(m.r)
		if err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		for _, c := range conns {
			if err := m.show(c); err != nil {
				return err
			}
		}
	}

	var answers <-chan string // nil, and so never ready, unless -ask
	if opts.ask {
		answers = readLines(stdin)
	}
	fmt.Fprintln(stderr, "conn-monitor: watching, Ctrl-C to stop")
	err = m.watch(ctx, rd, answers)

	printSummary(stderr, coll.Maps["flows"], m.r)
	if opts.block {
		printRules(stderr, m.rules)
	}

	return err
}

// parseFlags reads the command line. Usage goes to stderr.
func parseFlags(args []string, stderr io.Writer) (options, error) {
	var opts options
	fs := flag.NewFlagSet("conn-monitor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&opts.asJSON, "json", false, "print one JSON object per line instead of text")
	fs.BoolVar(&opts.list, "list", false, "print the hooks in this binary and exit")
	fs.StringVar(&opts.skip, "skip", "", "comma-separated program names not to attach (see -list)")
	fs.BoolVar(&opts.noDrops, "no-drops", false, "don't report packets the kernel throws away (same as -skip handle_kfree_skb)")
	fs.BoolVar(&opts.noSnapshot, "no-snapshot", false, "don't print the sockets that already exist at startup")
	fs.StringVar(&opts.ignoreDrops, "ignore-drops", "queue_purge", "comma-separated drop reasons not to print (kernel bookkeeping)")
	fs.BoolVar(&opts.block, "block", false, "arm the block module: decide new connections by the rules")
	fs.StringVar(&opts.rulesFile, "rules", "", "with -block: the rules file to load, and to append prompt answers to")
	fs.StringVar(&opts.defaultAction, "default", "allow", "with -block: what applies when no rule matches, allow or deny")
	fs.BoolVar(&opts.ask, "ask", false, "with -block: prompt for a rule when an attempt matches none")
	fs.StringVar(&opts.cgroup, "cgroup", "", "with -block: the cgroup v2 mount to attach to (default: found in /proc/self/mountinfo)")

	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if opts.defaultAction != "allow" && opts.defaultAction != "deny" {
		return options{}, fmt.Errorf("-default must be allow or deny, got %q", opts.defaultAction)
	}
	if !opts.block && (opts.ask || opts.rulesFile != "" || opts.cgroup != "") {
		return options{}, errors.New("-ask, -rules and -cgroup only mean something with -block")
	}

	return opts, nil
}

// monitor is the printing side of conn-monitor: where events go, which drops to
// leave out, and the rules map that prompt answers are written to.
type monitor struct {
	r         *resolver
	enc       *json.Encoder   // set for -json; nil means the text format
	ignored   map[string]bool // drop reasons not to print
	rules     *ebpf.Map       // nil without the block module
	rulesFile string          // where prompt answers are also saved; "" for nowhere
	stdout    io.Writer       // events
	stderr    io.Writer       // notes and prompts
}

// show prints one connection in the chosen format.
func (m *monitor) show(c connection) error {
	if m.enc != nil {
		return m.enc.Encode(c)
	}
	return printText(m.stdout, c)
}

// watch is the event loop: events decoded from the ring buffer by a
// goroutine, and lines typed on the terminal (only with -ask) that answer
// the prompts in the order they were asked. It returns nil when ctx is done,
// which closes the ring buffer and so ends the reader.
func (m *monitor) watch(ctx context.Context, rd *ringbuf.Reader, answers <-chan string) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()  // last: the reader has been unblocked by then
	defer rd.Close() // makes a blocked Read return
	defer cancel()   // makes a blocked send on events return
	stopClosing := context.AfterFunc(ctx, func() { rd.Close() })
	defer stopClosing()

	events := make(chan monitorEvent)
	readErr := make(chan error, 1) // the reader sends once and exits
	wg.Go(func() { readErr <- readEvents(ctx, rd, events) })

	var pending []connection // attempts shown with a prompt, oldest first
	for {
		select {
		case err := <-readErr:
			if ctx.Err() != nil || errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err
		case ev := <-events:
			c := m.r.enrich(ev)
			if c.Kind == "drop" && m.ignored[c.Reason] {
				continue
			}
			if err := m.show(c); err != nil {
				return err
			}
			if c.Kind == "ask" && answers != nil {
				pending = append(pending, c)
				askPrompt(m.stderr, c)
			}
		case line, ok := <-answers:
			if !ok {
				answers = nil // the terminal went away; stop prompting
				continue
			}
			if len(pending) == 0 {
				continue
			}
			c := pending[0]
			pending = pending[1:]
			text, err := applyAnswer(line, c, m.rules, m.rulesFile)
			if err != nil {
				fmt.Fprintln(m.stderr, "conn-monitor:", err)
				continue
			}
			if text != "" {
				fmt.Fprintln(m.stderr, "conn-monitor: rule added:", text)
			}
		}
	}
}

// readEvents decodes events from the ring buffer and hands them to the
// loop until the reader is closed, decoding fails, or ctx is done.
func readEvents(ctx context.Context, rd *ringbuf.Reader, events chan<- monitorEvent) error {
	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			return err
		}
		var ev monitorEvent
		if _, err := binary.Decode(rec.RawSample, binary.NativeEndian, &ev); err != nil {
			return fmt.Errorf("decode event: %w", err)
		}
		select {
		case events <- ev:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// readLines delivers each line typed on r, for the prompt, and closes the
// channel at end of input. The goroutine ends with the input, which for a
// terminal means with the process: a read on a terminal can't be interrupted.
func readLines(r io.Reader) <-chan string {
	lines := make(chan string)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	return lines
}

// splitList turns a comma-separated flag value into a set.
func splitList(s string) map[string]bool {
	set := make(map[string]bool)
	for item := range strings.SplitSeq(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			set[item] = true
		}
	}
	return set
}

// listHooks prints each program in the compiled object and the hook it
// attaches to.
func listHooks(w io.Writer, spec *ebpf.CollectionSpec) {
	for _, name := range slices.Sorted(maps.Keys(spec.Programs)) {
		fmt.Fprintf(w, "%-28s %s\n", name, spec.Programs[name].SectionName)
	}
}

// attachAll attaches every program in the compiled object where its section
// name says to. That is all the Go side needs to know about the kernel side,
// so modules can come and go in bpf/ without changes here. skip names
// programs to leave unattached, with a note to print or "" for silence. A
// hook whose kernel function or tracepoint doesn't exist is skipped with a
// note. The links are returned even on error, so the caller can close them.
func attachAll(spec *ebpf.CollectionSpec, coll *ebpf.Collection, skip map[string]string, cgroup string, stderr io.Writer) ([]link.Link, error) {
	var links []link.Link
	var noKprobes []string // kprobe hooks a kernel without kprobe support can't take

	for _, name := range slices.Sorted(maps.Keys(coll.Programs)) {
		if note, ok := skip[name]; ok {
			if note != "" {
				fmt.Fprintf(stderr, "conn-monitor: %s %s\n", name, note)
			}
			continue
		}

		ps := spec.Programs[name]
		l, err := attach(ps, coll.Programs[name], cgroup)

		switch {
		case errors.Is(err, os.ErrNotExist) && isKprobe(ps.SectionName) && !kprobesSupported():
			noKprobes = append(noKprobes, name)
			continue
		case errors.Is(err, os.ErrNotExist):
			fmt.Fprintf(stderr, "conn-monitor: %s is not in this kernel, skipping %s\n", ps.SectionName, name)
			continue
		case err != nil:
			return links, fmt.Errorf("attach %s (%s): %w", name, ps.SectionName, err)
		}

		links = append(links, l)
	}

	if len(noKprobes) > 0 {
		fmt.Fprintf(stderr, "conn-monitor: this kernel can't attach kprobes (built without CONFIG_KPROBES), skipping %s\n", strings.Join(noKprobes, ", "))
	}

	return links, nil
}

// isKprobe says whether a section names a kprobe or kretprobe hook.
func isKprobe(section string) bool {
	kind, _, _ := strings.Cut(section, "/")
	return kind == "kprobe" || kind == "kretprobe"
}

// kprobesSupported reports whether this kernel can attach kprobes at all,
// through the perf kprobe PMU or the kprobe_events file in tracefs. Kernels
// built without CONFIG_KPROBES (some minimal VM kernels) have neither, and
// then every kprobe hook fails the same way a missing function would.
func kprobesSupported() bool {
	for _, p := range []string{
		"/sys/bus/event_source/devices/kprobe",
		"/sys/kernel/tracing/kprobe_events",
		"/sys/kernel/debug/tracing/kprobe_events",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// attach hooks one program according to its section name: kprobe/<function>,
// kretprobe/<function>, tracepoint/<group>/<name>, or cgroup/<hook>, which
// goes on the root of the cgroup tree so it applies to every process. A
// module that needs another kind of hook adds a case here.
func attach(ps *ebpf.ProgramSpec, prog *ebpf.Program, cgroup string) (link.Link, error) {
	kind, target, _ := strings.Cut(ps.SectionName, "/")

	switch kind {
	case "kprobe":
		return link.Kprobe(target, prog, nil)
	case "kretprobe":
		return link.Kretprobe(target, prog, nil)
	case "tracepoint":
		group, name, ok := strings.Cut(target, "/")
		if !ok {
			return nil, fmt.Errorf("section %q: a tracepoint needs group/name", ps.SectionName)
		}
		return link.Tracepoint(group, name, prog, nil)
	case "cgroup":
		return link.AttachCgroup(link.CgroupOptions{Path: cgroup, Attach: ps.AttachType, Program: prog})
	}

	return nil, fmt.Errorf("section %q: don't know how to attach this kind of hook", ps.SectionName)
}
