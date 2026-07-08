// Command tcpcap captures TCP packets on a network interface and outputs
// them as structured data (JSON Lines / JSON array / text) that is easy for
// other programs to parse.
//
// It is similar to tcpdump but focused on TCP with structured output,
// exposing TCP-specific fields (seq, ack, flags, window) in a parseable
// form, solving the problem that tcpdump text is hard to parse programmatically.
//
// Examples:
//
//	tcpcap --list-interfaces
//	tcpcap -i eth0                  # capture all TCP (default JSON Lines)
//	tcpcap -i eth0 -p 80            # capture port 80 (HTTP)
//	tcpcap -i eth0 -f text          # text output
//	tcpcap -i eth0 -o out.jsonl     # output to file
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
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
		fmt.Fprintln(out, "  tcpcap -i <interface> [options]")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  tcpcap --list-interfaces")
		fmt.Fprintln(out, "  tcpcap -i eth0                       # capture all TCP on eth0 (default JSON Lines)")
		fmt.Fprintln(out, "  tcpcap -i eth0 -p 80                 # capture port 80 (HTTP)")
		fmt.Fprintln(out, "  tcpcap -i eth0 -f text               # text output")
		fmt.Fprintln(out, "  tcpcap -i eth0 -o out.jsonl          # output to file")
		fmt.Fprintln(out, "  tcpcap -i eth0 -bpf \"tcp port 443\"   # custom BPF")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Options:")
		flag.PrintDefaults()
	}

	listIfaces := flag.Bool("list-interfaces", false, "list all available network interfaces and exit")
	iface := flag.String("i", "", "network interface name (required; use --list-interfaces to see them)")
	format := flag.String("f", "jsonl", "output format: jsonl (default, JSON Lines) | json (JSON array) | text")
	outFile := flag.String("o", "", "output file path (default: stdout)")
	bpf := flag.String("bpf", "", "raw BPF filter expression (overrides IP/port filters below when set)")
	srcIP := flag.String("src-ip", "", "filter by source IP")
	dstIP := flag.String("dst-ip", "", "filter by destination IP")
	srcPort := flag.Int("src-port", 0, "filter by source port")
	dstPort := flag.Int("dst-port", 0, "filter by destination port")
	port := flag.Int("p", 0, "filter by port (source or destination)")
	noPayload := flag.Bool("no-payload", false, "do not output payload content (metadata only)")
	maxPayload := flag.Int("max-payload", 256, "max payload bytes to display (0 = unlimited)")
	snapLen := flag.Int("snaplen", 65536, "snapshot length in bytes")
	promisc := flag.Bool("promisc", false, "enable promiscuous mode (capture traffic not addressed to this host)")
	timeoutSec := flag.Int("timeout", 0, "read timeout in seconds (0 = block forever)")

	flag.Parse()

	if *listIfaces {
		os.Exit(listInterfaces())
	}
	if *iface == "" {
		fmt.Fprintln(os.Stderr, "error: -i is required (use --list-interfaces to see available interfaces)")
		flag.Usage()
		os.Exit(2)
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
		SnapLen:        *snapLen,
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

	var count int64
	handler := func(p *packet.TCPPacket) {
		atomic.AddInt64(&count, 1)
		if err := writer.Write(p); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		}
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- capture.Capture(ctx, cfg, handler)
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\n[interrupted] stopping capture...")
		<-errCh // wait for Capture to fully return so the writer finalizes properly
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			fmt.Fprintf(os.Stderr, "capture error: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "captured %d TCP packets\n", atomic.LoadInt64(&count))
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

// listInterfaces lists all available network interfaces. Returns the exit code.
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
		fmt.Printf("%-46s %s\n", d.Name, desc)
	}
	return 0
}
