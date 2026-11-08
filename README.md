#### Real-time Linux network monitoring and connection control with Go and eBPF.

Which programs are communicating over the network? Where are they connecting? What is listening on a port, and why are certain packets being dropped?

`conn-monitor` provides real-time visibility into network activity on a Linux machine, showing the processes responsible for connections and traffic as they happen.
Built with `Go` and `eBPF`, it monitors outgoing and incoming traffic, listening sockets, packet capture activity, and kernel packet drops.

When it starts, it takes a snapshot of existing TCP and UDP sockets. From that point on, it reports new network activity as it occurs, including the associated program,
user, protocol, and network endpoints where available.

Beyond monitoring, `conn-monitor` can also enforce connection rules.

With `-block` enabled:
- rules define which programs may communicate with which destinations.
- `eBPF` programs enforce those rules directly in the kernel, at the `connect()` and `sendto()` hooks.
- denied attempts fail with `Operation not permitted (EPERM)`, before any packet is sent.

Rules are stored in a simple text file and can also be added interactively from the terminal while `conn-monitor` runs.

The implementation is deliberately lightweight. The kernel-side functionality is divided into small `eBPF modules`, each with a specific responsibility. 
These modules are compiled into BPF bytecode and embedded into the Go executable at build time.

The result is a single binary, with no graphical interface and no permanent kernel installation. 
It runs with root privileges, and when the process exits, its `eBPF hooks` and connection enforcement are removed.

**`conn-monitor` is an experimental and educational project**, intended to explore Linux network observability and kernel-level connection control through eBPF.
The code, the implementation, and the experiments below are all part of that exploration.

#### Contents

- [What it reports](#what-it-reports)
- [How it compares to OpenSnitch](#how-it-compares-to-opensnitch)
- [Requirements](#requirements)
- [Build](#build)
- [Run it](#run-it)
- [Experiments](#experiments)

#### What it reports

Nine kinds of lines:

- `snap`: the starting picture, taken once from `/proc` right after the hooks are attached: every TCP and UDP socket a program holds, with its state (`LISTEN`, `ESTABLISHED`, `UNCONN`, ...).
Events only ever report what changes; this is what they change from.
- `out` / `in`: every TCP connection a machine opens or accepts, and datagram traffic a process sends or receives: UDP (DNS, NTP, QUIC, WARP, mDNS, ...), ICMP (ping), raw sockets, and SCTP.
Datagrams have no connections, only packets, so they are reported as *flows*: one line per (program, protocol, remote host), repeated at most once a minute, with a count of what was suppressed in between.
- `listen` / `unlisten`: a program started, or stopped, listening on a TCP port.
- `cap`: a program opened a packet socket, the kind that works *below* IP. That is `tcpdump` starting a capture, `arping`, `nmap's ARP scan`, or a `DHCP` client getting ready.
Frames sent through such a socket appear as `out packet` flows.
- `drop`: the kernel threw a packet away, with the reason: a SYN to a port nobody listens on, a packet dropped by the firewall, a reset, a bad checksum. 
These are the packets that never reach any program. One line per (scanner, port, reason) per minute, so a port scan shows which ports were tried and how often.
- `denied`: a rule refused a program's connection attempt. The program got `EPERM`; no packet left. Only with `-block`.
- `ask`: an attempt no rule covered; the default policy was applied (allowed or denied), and with `-ask` a prompt lets you turn the answer into a rule. Only with `-block`.

#### How it compares to OpenSnitch

`OpenSnitch`:
- uses `iptables` or `nftables` rules to send selected packets to `NFQUEUE` (typically the initial TCP SYN packet, but potentially multiple UDP packets) 
- receives and parses intercepted packets in userspace 
- attempts to identify the originating process using `/proc`, `netlink`, or eBPF-based monitoring
- evaluates existing rules in the daemon; if no rule matches, it may ask the UI or apply a default action 
- returns an allow/drop verdict to Netfilter while the packet is queued, using a secondary queue when waiting for interactive decisions

`conn-monitor` instead attaches four eBPF programs to the root of the cgroup tree, at the kernel's `connect()`/`sendto()` hooks: 
- they run inside the calling program
- look the program and destination up in a rules map
- return allow or refuse 

No packet is queued, the decision costs a few map lookups, and the program's identity is simply "whoever is calling".

#### Requirements

- Ubuntu 26.04 LTS (any recent `Linux` with `BTF`, `cgroup v2` and `kprobes` works; the kernel needs `CONFIG_DEBUG_INFO_BTF`, which Ubuntu kernels ship)
- Go 1.27.3 or newer
- To build the kernel side: `clang`, `llvm` (for `llvm-strip`), the `libbpf` headers and `bpftool`. The generated bindings are committed, so `go build` alone works without them; you need them to change anything in `bpf/`
- Root to run

#### Build

#### 1. Install the tools

```bash
sudo apt update
sudo apt install clang llvm libbpf-dev bpftool
```

What each is for: 
- `clang` compiles C to BPF bytecode (gcc can't) 
- `llvm` provides `llvm-strip`, which the generator uses 
- `libbpf-dev` provides the `bpf/*.h` helper headers the C files include 
- `bpftool` generates `vmlinux.h` 

Install `Go`:

```bash
sudo bash tool/install-go.sh
export PATH="....."
go version
```

Install `golangci-lint v2`

```bash
sudo bash tool/install-golangci-lint.sh
export PATH="....."
golangci-lint version
```

Sanity checks:

```bash
ls -l /sys/kernel/btf/vmlinux
sudo grep -wE 'tcp_connect|inet_csk_accept|udp_sendmsg|udpv6_sendmsg|ping_v4_sendmsg|ping_v6_sendmsg|raw_sendmsg|rawv6_sendmsg|sctp_sendmsg|skb_consume_udp|skb_free_datagram|packet_create|packet_bind|packet_sendmsg' /proc/kallsyms

sudo cat /sys/kernel/tracing/events/skb/kfree_skb/format
sudo cat /sys/kernel/tracing/events/sock/inet_sock_set_state/format
sudo cat /sys/kernel/tracing/events/sched/sched_process_exec/format

stat -fc %T /sys/fs/cgroup
```

The first file is the kernel's description of its own data structures (`BTF`); everything below depends on it, and Ubuntu kernels ship it.

The second command lists the kernel functions our `kprobes` attach to. 
Expect one line per name, some with a `.cold` companion; `T` means an exported function, `t` a file-local one, and both can be hooked. 
`sctp_sendmsg` is normally absent: SCTP is a kernel module that is loaded only when something uses it, and `conn-monitor` skips it with a note. 
Kernel functions are not a stable interface, which is why we check.

The three `cat`s print the records of the tracepoints, the stable kind of hook. 
- `kfree_skb` gives us a dropped packet (`skbaddr`), the `reason`, and on recent kernels the receiving socket (`rx_sk`) 
- `inet_sock_set_state` gives us a TCP socket (`skaddr`) changing from `oldstate` to `newstate`
- `sched_process_exec` gives us the path of every program that starts (filename, stored as a "data location", an offset into the record)

The last command must print `cgroup2fs`: the `block` module attaches to the root of the cgroup tree, and that only works with `cgroup v2`.

#### 2. Generate current kernel's types

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
grep -c 'SKB_DROP_REASON_' bpf/vmlinux.h
```

`vmlinux.h` is a C header, several megabytes, describing every structure in *your running kernel*, produced from the BTF file. Keep it in `bpf/` next to the `C `files that include it.

Our `C` code needs the layout of: 
- `struct sock` 
- `struct msghdr` 
- `struct sk_buff` 
- `struct dst_entry` 
- `struct packet_sock` 
- `struct bpf_sock_addr` 
- `struct task_struct` 
- `struct inode`
- and the tracepoint records

Rather than installing kernel headers that might not match, we ask the kernel itself. 

This header is also what makes the `"compile once, run everywhere"` (`CO-RE`) machinery work: the compiler records *which field* we touch, and at load time the library adjusts the offsets 
to whatever kernel is running, so the binary survives kernel updates.

The `grep -c` prints a number in the hundreds: the `drop reasons` this kernel knows. 
Their numbers differ between kernel versions, so `conn-monitor` reads their names from the kernel at startup instead of hard-coding them.

#### 3. Generate the bindings, test, build

```bash
go generate ./...
go vet ./...
go test ./...
go build -o bin/conn-monitor .
```

- `go generate` runs the `//go:generate` line in `main.go`, which runs `bpf2go` from `github.com/cilium/ebpf`, the `Go library` that talks to the kernel's BPF `system call` (load programs, create maps,
attach hooks, read ring buffers, read maps, read kernel types). It calls `clang` on `bpf/monitor.bpf.c` (and, through its includes, on every module), strips debug info, and writes two files into the project root,
`monitor_x86_bpfel.go` and `monitor_x86_bpfel.o` (`arm64` instead of `x86` on an ARM machine: the target is `native`, the architecture of the machine running `go generate`). 

- The `.o` is the compiled `BPF` bytecode; the `.go` embeds it and defines `loadMonitor`, a Go struct for every map's key and value, and, because the line says `-type event`, `monitorEvent` for the one 
struct that is not a map type. 

Don't edit these; rerun `go generate` after any change in `bpf/`. Regenerate when you change the `C` code.

#### Run it

Build as your user, run as root. 

Start by asking the binary what it contains; this needs no root:

```bash
./bin/conn-monitor -list
```
```
block_connect4               cgroup/connect4
block_connect6               cgroup/connect6
block_sendmsg4               cgroup/sendmsg4
block_sendmsg6               cgroup/sendmsg6
handle_accept                kretprobe/inet_csk_accept
handle_connect               kprobe/tcp_connect
handle_exec                  tracepoint/sched/sched_process_exec
handle_kfree_skb             tracepoint/skb/kfree_skb
handle_packet_bind           kprobe/packet_bind
handle_packet_create         kprobe/packet_create
handle_packet_sendmsg        kprobe/packet_sendmsg
handle_ping_v4_sendmsg       kprobe/ping_v4_sendmsg
handle_ping_v6_sendmsg       kprobe/ping_v6_sendmsg
handle_raw_sendmsg           kprobe/raw_sendmsg
handle_rawv6_sendmsg         kprobe/rawv6_sendmsg
handle_sctp_sendmsg          kprobe/sctp_sendmsg
handle_set_state             tracepoint/sock/inet_sock_set_state
handle_skb_consume_udp       kprobe/skb_consume_udp
handle_skb_free_datagram     kprobe/skb_free_datagram
handle_udp_sendmsg           kprobe/udp_sendmsg
handle_udpv6_sendmsg         kprobe/udpv6_sendmsg
```

21 programs, each with the hook its section names; that list is the entire contract between the `C` and the `Go`. The four `cgroup/` ones are the `block` module.

Then:

```bash
sudo ./bin/conn-monitor
```
```
conn-monitor: 4 block hooks present but not armed; start with -block to enforce rules
conn-monitor: kprobe/sctp_sendmsg is not in this kernel, skipping handle_sctp_sendmsg
15:04:38.330  snap      tcp        amazon-ssm-agen[1096]   root                  x.x.x.x:x -> x.x.x.x:x ESTABLISHED  /snap/amazon-ssm-agent/13349/amazon-ssm-agent
15:04:38.330  snap      udp        chronyd[813]            root                  x.x.x.x:x UNCONN  /usr/sbin/chronyd
15:04:38.330  snap      udp        chronyd[813]            root                  [x]:x UNCONN  /usr/sbin/chronyd
15:04:38.330  snap      tcp        sshd[2383]              root                  x.x.x.x:x LISTEN  /usr/sbin/sshd
15:04:38.330  snap      tcp        sshd[2383]              root                  [x]:x LISTEN  /usr/sbin/sshd
15:04:38.330  snap      tcp        sshd-session[1586]      root                  x.x.x.x:x <- x.x.x.x:x ESTABLISHED  /usr/lib/openssh/sshd-session
15:04:38.330  snap      udp        systemd-network[2425]   systemd-network       x.x.x.x:x UNCONN  /usr/lib/systemd/systemd-networkd
15:04:38.330  snap      tcp        systemd-resolve[2379]   systemd-resolve       x.x.x.x:x LISTEN  /usr/lib/systemd/systemd-resolved
15:04:38.330  snap      udp        systemd-resolve[2379]   systemd-resolve       x.x.x.x:x UNCONN  /usr/lib/systemd/systemd-resolved
15:04:38.330  snap      tcp        systemd-resolve[2379]   systemd-resolve       x.x.x.x:x LISTEN  /usr/lib/systemd/systemd-resolved
15:04:38.330  snap      udp        systemd-resolve[2379]   systemd-resolve       x.x.x.x:x UNCONN  /usr/lib/systemd/systemd-resolved
conn-monitor: watching, Ctrl-C to stop
15:04:51.394  out       udp        chronyd[813]            _chrony               x.x.x.x:x -> x.x.x.x:x  /usr/sbin/chronyd
15:05:08.740  out       udp        chronyd[813]            _chrony               x.x.x.x:x -> x.x.x.x:x  /usr/sbin/chronyd
15:05:09.206  out       udp        chronyd[813]            _chrony               x.x.x.x:x -> x.x.x.x:x  /usr/sbin/chronyd
15:05:10.339  out       udp        chronyd[813]            _chrony               x.x.x.x:x -> x.x.x.x:x  /usr/sbin/chronyd
```

The first two lines are expected: the `block` module is present but needs `-block`, and SCTP is a kernel module that isn't loaded.

Flags:

| Flag | Meaning |
|---|---|
| `-list` | print the `hooks` in this binary and exit (no root needed) |
| `-json` | one JSON object per line instead of text |
| `-no-snapshot` | don't print the sockets that already exist at startup |
| `-no-drops` | don't report packets the kernel throws away (same as `-skip handle_kfree_skb`) |
| `-ignore-drops reasons` | comma-separated drop reasons not to print; default `queue_purge` (kernel bookkeeping); `-ignore-drops ""` shows everything |
| `-skip names` | comma-separated program names from `-list` not to attach |
| `-block` | arm the `block` module: decide new connections by the rules |
| `-rules file` | with `-block`: the rules file to load, and to append prompt answers to |
| `-default allow\|deny` | with `-block`: what applies when no rule matches (default `allow`) |
| `-ask` | with `-block`: prompt for a rule when an attempt matches none |
| `-cgroup path` | with `-block`: the cgroup v2 mount to attach to (default: found in `/proc/self/mountinfo`) |

Events go to stdout, everything else (notes, prompts, the summaries on exit) to stderr, so `sudo ./bin/conn-monitor -json >> connections.jsonl` records cleanly.

#### Experiments

Find your interface name for the experiments below with `ip -br link` (`ens5` on most EC2 instances; `eth0` on older ones). 

The outputs shown come from an EC2 instance; yours will differ in addresses and names.

**1. Outgoing, with DNS.** 

In a second terminal:

```bash
curl -sS https://example.com -o /dev/null
```
```
16:16:19.478  out       udp        curl[7009]              ubuntu                x.x.x.x:x -> x.x.x.x:x  /usr/bin/curl
16:16:19.478  in        udp        systemd-resolve[2379]   systemd-resolve       x.x.x.x:x <- x.x.x.x:x  /usr/lib/systemd/systemd-resolved
16:16:19.478  out       udp        systemd-resolve[2379]   systemd-resolve       x.x.x.x:x -> x.x.x.x:x  /usr/lib/systemd/systemd-resolved
16:16:19.483  out       tcp        curl[7009]              ubuntu                x.x.x.x:x -> x.x.x.x:x  /usr/bin/curl
```

That is the whole story of one `curl`: curl asks the local stub resolver (UDP to x.x.x.x), the resolver receives the question, forwards it to the VPC's DNS server (`x.x.x.x` on EC2),
and curl connects over TCP. 

Run the same `curl` again within a minute: only the TCP line appears, because the three UDP flows were reported less than 60 seconds ago; their repeats are counted.

**2. A door opens, a connection comes in, the door shuts.** 

Terminal 2 and 3:

```bash
python3 -m http.server 8000
curl -s http://127.0.0.1:8000/ -o /dev/null
```
```
16:37:33.710  listen    tcp        python3[7504]           ubuntu                0.0.0.0:8000  /usr/bin/python3.14
16:37:55.153  out       tcp        curl[7511]              ubuntu                127.0.0.1:53486 -> 127.0.0.1:8000  /usr/bin/curl
16:37:55.153  in        tcp        python3[7504]           ubuntu                127.0.0.1:8000 <- 127.0.0.1:53486  /usr/bin/python3.14
```

The `listen` line appears the moment the server starts, before anyone connects; the connection is then seen from both ends (curl's `connect()`, python's `accept()`; the port numbers match crosswise).

Press Ctrl-C in terminal 2:

```
16:39:54.382  unlisten  tcp        python3[7504]           ubuntu                0.0.0.0:8000  /usr/bin/python3.14
```

**3. Incoming from outside.** 

Your current SSH session predates `conn-monitor`, so it is in the snapshot, not in the events. 

Open a *second* SSH connection from your laptop:

```
17:00:31.859  in        tcp        sshd[2383]              root                  x.x.x.x:22 <- x.x.x.x:50823  /usr/sbin/sshd
```

**4. ICMP.**

```bash
ping -c 3 8.8.8.8
```
```
17:03:40.861  out       raw-icmp   ping[7699]              ubuntu                x.x.x.x -> x.x.x.x  /usr/bin/ping
17:03:40.862  drop      icmp       -                       -                     x.x.x.x <- x.x.x.x  no_socket (ens5)
```

Three pings, one line: packets 2 and 3 are the same flow. 

Ubuntu's `ping` carries the `cap_net_raw` file capability, so it uses a raw socket even as a normal user (`raw-icmp`); on a system without that capability it falls back to an ICMP datagram socket and shows as `icmp`. 

No ports: ICMP has none. The second line is expected: the echo reply was delivered to ping's raw socket as a copy, and the kernel's own ICMP handler then looked for a ping-type socket for the original,
found none, and dropped it.

**5. Incoming UDP.** 

Terminal 2 listens, terminal 3 sends one datagram with bash's built-in `/dev/udp`:

```bash
python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 9999)); print(s.recvfrom(100))"
echo hi > /dev/udp/127.0.0.1/9999
```
```
17:10:22.720  out       udp        bash[6581]              ubuntu                127.0.0.1:45821 -> 127.0.0.1:9999  /usr/bin/bash
17:10:22.720  in        udp        python3[7763]           ubuntu                127.0.0.1:9999 <- 127.0.0.1:45821  /usr/bin/python3.14
```

**6. NTP.** 

On EC2, chrony uses the Amazon Time Sync Service and Ubuntu's pool. 

Force a poll:

```bash
sudo chronyc burst 4/4
```
```
17:14:06.630  out       udp        chronyd[813]            _chrony               x.x.x.x:x -> x.x.x.x:x [x1]  /usr/sbin/chronyd
```

Left running, `chronyd` produces one line per server per minute, each with `[x1]` or so: that is the window working as designed. A longer `FLOW_WINDOW_NS` in `common.bpf.h` quiets it.

**7. A sniffer starts (packet sockets).** 

Capture one packet:

```bash
sudo tcpdump -i ens5 -c 1 -n
```
```
17:19:25.695  cap       packet     tcpdump[7858]           root                  ens5 all  /usr/bin/tcpdump
```

That is `tcpdump` binding a packet socket to `ens5` for every ethertype (`all`), the moment before it starts capturing.
The packets it then reads are not reported one by one; the capture starting is the signal.

If `iputils-arping` is installed, `sudo arping -c 1 -I ens5 172.31.0.1` shows the sending side too: a `cap` line for its socket, then `out packet arping[...] nobody ens5 -> ? all`.

```
17:24:14.290  cap       packet     arping[8087]            root                  any all  /usr/sbin/arping
17:24:14.296  cap       packet     arping[8087]            root                  ens5 all  /usr/sbin/arping
17:24:14.297  out       packet     arping[8087]            nobody                ens5 -> ? all  /usr/sbin/arping
```

The user is `nobody` because `arping` drops its privileges after opening the socket, and the MAC is `?` because this `arping` builds whole frames itself.

DHCP clients look the same when a lease is renewed from scratch; the periodic renewal is plain UDP (`systemd-network ... :68 -> ...:67`).

**8. A datagram to a port nobody listens on (drops).**

```bash
echo hi > /dev/udp/127.0.0.1/9
```
```
18:35:51.174  out       udp        bash[6241]              ubuntu                127.0.0.1:49770 -> 127.0.0.1:9  /usr/bin/bash
18:35:51.174  drop      udp        -                       -                     127.0.0.1:9 <- 127.0.0.1:49770  no_socket (lo)
```

The first line is bash sending.

The second is the kernel, on the receiving side of the loopback interface, finding no socket on port 9 and throwing the datagram away.

Nobody is charged: no program was involved.

**9. A port scan, from the inside.** 

Try three closed ports in a row, then one of them again:

```bash
for p in 9 10 11; do curl -m 1 http://127.0.0.1:$p/; done
curl -m 1 http://127.0.0.1:9/
```
```
18:40:50.649  out       tcp        curl[6634]              ubuntu                127.0.0.1:35980 -> 127.0.0.1:9  /usr/bin/curl
18:40:50.649  drop      tcp        -                       -                     127.0.0.1:9 <- 127.0.0.1:35980 SYN  no_socket (lo)
18:40:50.657  out       tcp        curl[6635]              ubuntu                127.0.0.1:36826 -> 127.0.0.1:10  /usr/bin/curl
18:40:50.657  drop      tcp        -                       -                     127.0.0.1:10 <- 127.0.0.1:36826 SYN  no_socket (lo)
18:40:50.665  out       tcp        curl[6636]              ubuntu                127.0.0.1:60822 -> 127.0.0.1:11  /usr/bin/curl
18:40:50.665  drop      tcp        -                       -                     127.0.0.1:11 <- 127.0.0.1:60822 SYN  no_socket (lo)

18:42:40.538  out       tcp        curl[6669]              ubuntu                127.0.0.1:40308 -> 127.0.0.1:9  /usr/bin/curl
```

One `drop` per port tried, each a SYN that found no socket. The fourth attempt, port 9 again, prints curl's `out` line but no `drop`: that one was counted. 

Wait a minute and run the last command once more:

```
18:47:53.010  out       tcp        curl[6690]              ubuntu                127.0.0.1:46030 -> 127.0.0.1:9  /usr/bin/curl
18:47:53.010  drop      tcp        -                       -                     127.0.0.1:9 <- 127.0.0.1:46030 SYN [x1]  no_socket (lo)
```

`[x1]`: one sighting was suppressed since the flow was last reported. A real scan from the internet looks the same, with the scanner's address instead of 127.0.0.1 and larger counts.

**10. The firewall drops it instead.** 

Add a temporary rule that drops that SYN on the way in, repeat, then remove the rule:

```bash
sudo iptables -I INPUT -i lo -p tcp --dport 9 -j DROP
curl -m 2 http://127.0.0.1:9/
sudo iptables -D INPUT -i lo -p tcp --dport 9 -j DROP
```
```
18:53:42.599  out       tcp        curl[6736]              ubuntu                127.0.0.1:32794 -> 127.0.0.1:9  /usr/bin/curl
18:53:42.599  drop      tcp        -                       -                     127.0.0.1:9 <- 127.0.0.1:32794 SYN  netfilter_drop (lo)
```

Same SYN, different reason, and `curl` now waits for its 2-second timeout instead of being refused: a dropped packet gets no answer.

`curl` retransmits the SYN during those 2 seconds; the retransmissions are the same flow and are counted, not repeated. 

Now drop it on the way *out*:

```bash
sudo iptables -I OUTPUT -o lo -p tcp --dport 9 -j DROP
curl -m 2 http://127.0.0.1:9/
sudo iptables -D OUTPUT -o lo -p tcp --dport 9 -j DROP
```
```
18:59:53.104  out       tcp        curl[6793]              ubuntu                127.0.0.1:54892 -> 127.0.0.1:9  /usr/bin/curl
18:59:53.104  drop      tcp        curl[6793]              ubuntu                127.0.0.1:54892 -> 127.0.0.1:9 SYN  netfilter_drop (lo)  /usr/bin/curl
```

This drop *is* charged to curl: the packet came from curl's socket, which `remember_owner` had recorded at the `out` line. 

At the OUTPUT hook the packet has a route but no device yet, and the drop module asks the route, hence `(lo)`. With `UFW` set to `deny outgoing`, every blocked program shows up like this.

**11. What was counted.** 

Press Ctrl-C in the `conn-monitor` terminal. Flows whose repeats were counted but not yet reported are listed from the kernel's own map:

```
^Cconn-monitor: repeats not yet reported when stopped (count, kind, protocol, program, target):
  x1       cap       packet    arping[6574]           any all
  x1       drop in   tcp       -                      127.0.0.1:9  netfilter_drop (lo)
  x1       drop in   tcp       -                      x.x.x.x:x  no_socket (ens5)
  x1       drop in   tcp       -                      x.x.x.x:x  no_socket (ens5)
  x1       drop out  tcp       curl[6793]             127.0.0.1:9  netfilter_drop (lo)
  x1       flow      udp       chronyd[827]           x.x.x.x
  x1       flow      udp       chronyd[827]           x.x.x.x
  x1       flow      udp       chronyd[827]           x.x.x.x
```

The `hooks` are removed when the process exits; nothing stays behind in the kernel. 

While it runs, `sudo bpftool prog list` and `sudo bpftool map list` show the programs and the maps (`events`, `flows`, `owners`, `exes`, `rules`, `settings`) loaded; after Ctrl-C they're gone.

**12. A rules file.** 

Create `rules.txt` (or start from `rules.example.txt`):

```
# action  program          destination
deny      /usr/bin/curl    *                 # curl may not open connections...
allow     /usr/bin/curl    127.0.0.53:53     # ...except asking the local DNS stub
allow     /usr/bin/curl    127.0.0.1:8000    # ...and the local test server
```

The order of lines doesn't matter: the kernel tries the most specific rule first (address and port, then address, then port, then the program alone, then the same four for `*`). 

Start `conn-monitor` with the module armed, and in a second terminal try `curl`:

```bash
sudo ./bin/conn-monitor -block -rules rules.txt
```
```
conn-monitor: block module armed: default allow, 3 rules
conn-monitor: kprobe/sctp_sendmsg is not in this kernel, skipping handle_sctp_sendmsg
...
```

```bash
curl -sS https://example.com -o /dev/null
```
```
curl: (7) Failed to connect to example.com port 443 after 3 ms: Could not connect to server
```
```
19:23:15.076  out       udp        curl[7084]              ubuntu                127.0.0.1:48715 -> 127.0.0.53:53  /usr/bin/curl
19:23:15.077  ask       udp        systemd-resolve[2376]   systemd-resolve       -> 127.0.0.1:48715  allowed by default, no rule  /usr/lib/systemd/systemd-resolved
19:23:15.077  denied    udp        curl[7084]              ubuntu                -> x.x.x.x:x  denied by rule  /usr/bin/curl
19:23:15.077  denied    udp        curl[7084]              ubuntu                -> x.x.x.x:x  denied by rule  /usr/bin/curl
19:23:15.077  denied    udp        curl[7084]              ubuntu                -> [x:x:x::x:x]:x  denied by rule  /usr/bin/curl
19:23:15.077  denied    udp        curl[7084]              ubuntu                -> [x:x:x::x:x]:x  denied by rule  /usr/bin/curl
19:23:15.078  denied    tcp        curl[7084]              ubuntu                -> [x:x:x::x:x]:x  denied by rule  /usr/bin/curl
19:23:15.078  denied    tcp        curl[7084]              ubuntu                -> x.x.x.x:x  denied by rule  /usr/bin/curl
19:23:15.078  denied    tcp        curl[7084]              ubuntu                -> [x:x:x::x:x]:x  denied by rule  /usr/bin/curl
19:23:15.078  denied    tcp        curl[7084]              ubuntu                -> x.x.x.x:x  denied by rule  /usr/bin/curl
```

The DNS question went through, the resolver did its job, and curl's TCP connect was refused inside the `connect()` call: there is no `out tcp curl` line,
because the TCP module's hook sits later than the decision and never ran, and curl got its error in 3 ms. 

Now the local server from experiment 2:

```bash
python3 -m http.server 8000      # terminal 2
curl -s http://127.0.0.1:8000/ -o /dev/null && echo ok
```
```
ok
```
```
19:43:02.237  out       tcp        curl[7743]              ubuntu                127.0.0.1:49030 -> 127.0.0.1:8000  /usr/bin/curl
19:43:02.237  in        tcp        python3[7737]           ubuntu                127.0.0.1:8000 <- 127.0.0.1:49030  /usr/bin/python3.14
```

Allowed by rule, so reported only as the ordinary `out`/`in` pair. 

Take the `allow ... 127.0.0.53:53` line out of the file and restart to see the other failure mode: 
- curl's `sendto()` to the stub resolver is refused 
- `conn-monitor` prints `denied udp curl -> 127.0.0.53:53 denied by rule`
- curl says `Could not resolve host: example.com`. 

A `deny program *` rule cuts the program's DNS too, and the allow line is how you make an exception.

**13. A rule for every program.** 

Add `deny * :23` to the file and restart. Any program trying port 23, telnet's port, gets refused, curl included:

```bash
curl -m 2 http://127.0.0.1:23/
```
```
19:53:40.983  denied    tcp        curl[7929]              ubuntu                -> 127.0.0.1:23  denied by rule  /usr/bin/curl
```

**14. The learning mode.** 

Stop `conn-monitor` and start it with the prompt on. 

Keep the default `allow`: with `-default deny` every new connection by every program is refused until a rule allows it.

```bash
sudo ./bin/conn-monitor -block -ask -rules rules.txt
```

In the second terminal run something no rule covers:

```bash
python3 -c "import urllib.request; urllib.request.urlopen('https://example.com').read(10)"
```

`conn-monitor` prints the attempt and asks:

```
19:58:36.011  ask       udp        python3[7983]           ubuntu                -> 127.0.0.53:53  allowed by default, no rule  /usr/bin/python3.14
? python3 -> 127.0.0.53:53 was allowed by default, no rule. Rule for /usr/bin/python3.14: [a]llow / [d]eny this destination, [A]llow / [D]eny everywhere, Enter to skip:
```

Type `a` and Enter. 

```
conn-monitor: rule added: allow /usr/bin/python3.14 127.0.0.53:53
```

The answer was appended to `rules.txt`. Other programs ask too while this mode is on. Enter skips a question. 

That is OpenSnitch's learning mode in a terminal, with one difference: `OpenSnitch` holds the first attempt while you decide, `conn-monitor` applies the default to it and your answer to the next.

**15. What the rules did.** 

Press Ctrl-C:

```
^Cconn-monitor: repeats not yet reported when stopped (count, kind, protocol, program, target):
  x1       ask       udp       systemd-resolved[2376] 127.0.0.1:33362
  x1       ask       udp       systemd-resolved[2376] 127.0.0.1:57642
  x1       ask       udp       systemd-resolved[2376] x.x.x.x:x
  x1       flow      udp       chronyd[827]           x.x.x.x
  x1       flow      udp       chronyd[827]           x.x.x.x
  x1       flow      udp       chronyd[827]           x.x.x.x
  x1       flow      udp       chronyd[827]           x.x.x.x
  x1       flow      udp       chronyd[827]           x.x.x.x
  x11      flow      udp       systemd-resolved[2376] 127.0.0.1
  x2       flow      udp       systemd-networkd[2415] x.x.x.x
  x3       flow      udp       python3[8082]          127.0.0.53
  x3       flow      udp       python3[8092]          127.0.0.53
  x5       flow      udp       chronyd[827]           x.x.x.x
  x5       flow      udp       systemd-resolved[2376] x.x.x.x
conn-monitor: rules and how often each decided:
  x0       allow /usr/bin/python3.14 127.0.0.53:53
  x96      allow /usr/sbin/chronyd *
```

Each rule appears once, spelled as it was written, with how many attempts it decided. Enforcement lives exactly as long as `conn-monitor` does.
