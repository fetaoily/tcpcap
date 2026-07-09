// Command tcpcap captures TCP packets on a network interface and outputs
// them as structured data (JSON Lines / JSON array / text) that is easy for
// other programs to parse.
//
// It is similar to tcpdump but focused on TCP with structured output,
// exposing TCP-specific fields (seq, ack, flags, window) in a parseable
// form, solving the problem that tcpdump text is hard to parse programmatically.
// Command-line flags are aligned with tcpdump where practical.
//
// Examples:
//
//	tcpcap -D                       # list interfaces
//	tcpcap                          # capture on the auto-selected default interface
//	tcpcap -i eth0                  # capture all TCP (default JSON Lines)
//	tcpcap -i eth0 -p 80            # capture port 80 only (HTTP)
//	tcpcap -i eth0 "tcp port 443"   # tcpdump-style BPF filter
//	tcpcap -i eth0 -c 100 -f text   # capture 100 packets, text output
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fetaoily/tcpcap/internal/capture"
	"github.com/fetaoily/tcpcap/internal/output"
	"github.com/fetaoily/tcpcap/internal/packet"

	"github.com/google/gopacket/pcap"
)

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "tcpcap - TCP packet capture with structured output")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  tcpcap [options] [filter expression]")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "The filter expression is positional and uses tcpdump BPF syntax, e.g.:")
		fmt.Fprintln(out, "  tcpcap -i eth0 \"tcp port 443\"")
		fmt.Fprintln(out, "  tcpcap -i eth0 \"src host 10.0.0.1 and tcp port 22\"")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  tcpcap -D                       # list interfaces (marks the default)")
		fmt.Fprintln(out, "  tcpcap                          # capture on the auto-selected default interface")
		fmt.Fprintln(out, "  tcpcap -i eth0                  # capture all TCP (default JSON Lines)")
		fmt.Fprintln(out, "  tcpcap -i eth0 -p 80            # capture port 80 (HTTP)")
		fmt.Fprintln(out, "  tcpcap -i eth0 -c 100 -f text   # capture 100 packets, text output")
		fmt.Fprintln(out, "  tcpcap -i eth0 -o out.jsonl     # output to file")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Options:")
		flag.PrintDefaults()
	}

	// -D / --list-interfaces: tcpdump-style short flag
	var listIfaces bool
	flag.BoolVar(&listIfaces, "D", false, "list available network interfaces and exit")
	flag.BoolVar(&listIfaces, "list-interfaces", false, "list available network interfaces and exit")

	iface := flag.String("i", "", "network interface (default: auto-select the first non-loopback interface with an address)")
	format := flag.String("f", "jsonl", "output format: jsonl (default, JSON Lines) | json (JSON array) | text")
	outFile := flag.String("o", "", "output file path (default: stdout)")
	bpf := flag.String("bpf", "", "BPF filter expression; positional args (tcpdump-style) are also accepted")
	count := flag.Int("c", 0, "exit after capturing this many packets (0 = unlimited)")
	srcIP := flag.String("src-ip", "", "filter by source IP")
	dstIP := flag.String("dst-ip", "", "filter by destination IP")
	srcPort := flag.Int("src-port", 0, "filter by source port")
	dstPort := flag.Int("dst-port", 0, "filter by destination port")
	port := flag.Int("p", 0, "filter by port (source or destination)")
	noPayload := flag.Bool("no-payload", false, "do not output payload content (metadata only)")
	maxPayload := flag.Int("max-payload", 256, "max payload bytes to display (0 = unlimited)")

	// -s / --snaplen: tcpdump-style short flag
	var snapLen int
	flag.IntVar(&snapLen, "s", 65536, "snapshot length in bytes")
	flag.IntVar(&snapLen, "snaplen", 65536, "snapshot length in bytes")

	promisc := flag.Bool("promisc", false, "enable promiscuous mode (capture traffic not addressed to this host)")
	timeoutSec := flag.Int("timeout", 0, "read timeout in seconds (0 = block forever)")

	flag.Parse()

	if listIfaces {
		os.Exit(listInterfaces())
	}

	// tcpdump-style positional BPF filter expression
	if posArgs := flag.Args(); len(posArgs) > 0 {
		posBPF := strings.Join(posArgs, " ")
		if *bpf != "" {
			fmt.Fprintln(os.Stderr, "error: cannot combine -bpf with a positional filter expression")
			os.Exit(2)
		}
		*bpf = posBPF
	}

	// Auto-select the default interface when -i is omitted (tcpdump-style)
	if *iface == "" {
		def, err := defaultInterface()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v (use -i to specify one, or -D to list)\n", err)
			os.Exit(2)
		}
		*iface = def
		fmt.Fprintf(os.Stderr, "[auto] using interface: %s\n", *iface)
	}

	out, closeOut, err := openOutput(*outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer closeOut()

	writer, err := output.NewWriter(*format, out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	defer writer.Close()

	cfg := capture.Config{
		Interface:      *iface,
		SnapLen:        snapLen,
		Promiscuous:    *promisc,
		Timeout:        time.Duration(*timeoutSec) * time.Second,
		BPFFilter:      *bpf,
		IncludePayload: !*noPayload,
		MaxPayload:     *maxPayload,
		UserFilter: capture.Filter{
			SrcIP:   *srcIP,
			DstIP:   *dstIP,
			SrcPort: *srcPort,
			DstPort: *dstPort,
			Port:    *port,
		},
	}

	// Graceful shutdown on Ctrl+C
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var n int64
	handler := func(p *packet.TCPPacket) {
		atomic.AddInt64(&n, 1)
		if err := writer.Write(p); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		}
		// Stop after -c packets
		if *count > 0 && atomic.LoadInt64(&n) >= int64(*count) {
			stop()
		}
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- capture.Capture(ctx, cfg, handler)
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\n[stopped] finishing up...")
		<-errCh // wait for Capture to fully return so the writer finalizes properly
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			fmt.Fprintf(os.Stderr, "capture error: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "captured %d TCP packets\n", atomic.LoadInt64(&n))
}

// openOutput opens the output target. Returns stdout when path is empty.
func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("create output file %q: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// defaultInterface auto-selects a capture interface (tcpdump-style).
// Strategy (prefers the real primary NIC over virtual ones):
//  1. A physical interface owning the default-route IP (ideal).
//  2. The first physical interface (e.g. Wi-Fi/Ethernet), even if pcap did
//     not report an address for it.
//  3. Any interface owning the default-route IP (may be virtual).
//  4. The first non-loopback interface with an address.
func defaultInterface() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("list interfaces: %w", err)
	}

	localIP, _ := outboundLocalIP()

	// Physical interfaces only (exclude virtual/loopback), preserving order.
	var physical []pcap.Interface
	for _, d := range devs {
		if isLoopback(d) || isVirtual(d) {
			continue
		}
		physical = append(physical, d)
	}

	// 1. Physical interface owning the default-route IP
	if localIP != nil {
		for _, d := range physical {
			for _, a := range d.Addresses {
				if a.IP.Equal(localIP) {
					return d.Name, nil
				}
			}
		}
	}

	// 2. First physical interface (the typical primary NIC).
	if len(physical) > 0 {
		return physical[0].Name, nil
	}

	// 3. Any interface owning the default-route IP (may be virtual).
	if localIP != nil {
		for _, d := range devs {
			if isLoopback(d) {
				continue
			}
			for _, a := range d.Addresses {
				if a.IP.Equal(localIP) {
					return d.Name, nil
				}
			}
		}
	}

	// 4. First non-loopback interface with an address.
	for _, d := range devs {
		if isLoopback(d) || len(d.Addresses) == 0 {
			continue
		}
		return d.Name, nil
	}
	return "", fmt.Errorf("no usable network interface found")
}

// isVirtual reports whether the interface looks like a virtual/software NIC
// (VMware, Hyper-V, TAP, WAN Miniport, Wi-Fi Direct, etc.) rather than a
// physical adapter.
func isVirtual(d pcap.Interface) bool {
	s := strings.ToLower(d.Description + " " + d.Name)
	for _, k := range []string{
		"virtual", "vmware", "tap-w", "wan miniport", "bluetooth",
		"docker", "vethernet", "hyper-v", "wi-fi direct", "trustagent",
		"isatap", "teredo", "6to4", "tunnel",
	} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// outboundLocalIP returns the local IP address used to reach the internet
// (the default route). It opens a UDP "connection" which, for UDP, only
// resolves the route and binds the local address — no packets are sent.
func outboundLocalIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("unexpected local address type")
	}
	return addr.IP, nil
}

// isLoopback reports whether the interface is a loopback interface.
func isLoopback(d pcap.Interface) bool {
	if strings.Contains(strings.ToLower(d.Name), "loopback") {
		return true
	}
	for _, a := range d.Addresses {
		if a.IP.IsLoopback() {
			return true
		}
	}
	return false
}

// listInterfaces lists all available network interfaces and marks the default.
// Returns the exit code.
func listInterfaces() int {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to list interfaces: %v\n", err)
		fmt.Fprintln(os.Stderr, "hint: on Windows make sure Npcap is installed: https://npcap.com/")
		return 1
	}
	if len(devs) == 0 {
		fmt.Fprintln(os.Stderr, "no network interfaces found.")
		fmt.Fprintln(os.Stderr, "hint: on Windows make sure Npcap is installed: https://npcap.com/")
		return 1
	}
	defName, _ := defaultInterface()
	fmt.Printf("%-46s %s\n", "Interface (-i)", "Description / Addresses")
	fmt.Println(strings.Repeat("-", 100))
	for _, d := range devs {
		var addrs []string
		for _, a := range d.Addresses {
			addrs = append(addrs, a.IP.String())
		}
		desc := d.Description
		switch {
		case desc != "" && len(addrs) > 0:
			desc = desc + " (" + strings.Join(addrs, ", ") + ")"
		case desc == "" && len(addrs) > 0:
			desc = strings.Join(addrs, ", ")
		}
		mark := ""
		if d.Name == defName {
			mark = "  <- default"
		}
		fmt.Printf("%-46s %s%s\n", d.Name, desc, mark)
	}
	return 0
}
