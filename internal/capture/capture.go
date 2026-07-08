// Package capture wraps libpcap (gopacket) based TCP packet capturing.
//
// Filtering is done in kernel space via BPF (efficient). User-provided
// IP/port conditions are automatically translated into a BPF expression.
package capture

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fetaoily/tcpcap/internal/packet"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Filter defines IP/port based filter conditions.
// These conditions are translated into a BPF expression and applied in kernel space.
type Filter struct {
	SrcIP   string // source IP
	DstIP   string // destination IP
	SrcPort int    // source port
	DstPort int    // destination port
	Port    int    // source or destination port
}

// Config holds the capture configuration.
type Config struct {
	Interface      string        // network interface name
	SnapLen        int           // snapshot length in bytes
	Promiscuous    bool          // enable promiscuous mode
	Timeout        time.Duration // read timeout (0 or negative means block forever)
	BPFFilter      string        // raw BPF expression (highest priority; ignores UserFilter when set)
	UserFilter     Filter        // user filter conditions (auto-converted to BPF)
	IncludePayload bool          // whether to capture payload content
	MaxPayload     int           // max payload bytes to show (<= 0 means unlimited)
}

// Handler processes a parsed TCP packet.
type Handler func(*packet.TCPPacket)

// Capture starts capturing and processes each TCP packet.
// When ctx is canceled (e.g. Ctrl+C), it closes the underlying handle and returns ctx.Err().
func Capture(ctx context.Context, cfg Config, handler Handler) error {
	if cfg.Interface == "" {
		return fmt.Errorf("network interface is required")
	}
	if cfg.SnapLen <= 0 {
		cfg.SnapLen = 65536
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = pcap.BlockForever
	}

	// Open via InactiveHandle (three-stage) for fine control over promisc/snaplen/timeout
	inactive, err := pcap.NewInactiveHandle(cfg.Interface)
	if err != nil {
		return fmt.Errorf("open interface %s: %w", cfg.Interface, err)
	}
	defer inactive.CleanUp()

	if err := inactive.SetPromisc(cfg.Promiscuous); err != nil {
		return fmt.Errorf("set promisc: %w", err)
	}
	if err := inactive.SetSnapLen(cfg.SnapLen); err != nil {
		return fmt.Errorf("set snaplen: %w", err)
	}
	if err := inactive.SetTimeout(cfg.Timeout); err != nil {
		return fmt.Errorf("set timeout: %w", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return fmt.Errorf("activate handle: %w", err)
	}
	defer handle.Close()

	// Apply BPF filter (kernel-space filtering: only matching packets reach userspace)
	if bpf := buildBPF(cfg); bpf != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			return fmt.Errorf("set BPF filter %q: %w", bpf, err)
		}
	}

	// Watch for cancellation: on ctx cancel, close the handle to interrupt the blocking read
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			handle.Close()
		case <-stop:
		}
	}()
	defer close(stop)

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for p := range src.Packets() {
		tcp := packet.FromPacket(p, cfg.Interface, cfg.IncludePayload, cfg.MaxPayload)
		if tcp == nil {
			continue
		}
		handler(tcp)

		if ctx.Err() != nil {
			break
		}
	}

	return ctx.Err()
}

// buildBPF builds a BPF filter expression from Config.
// If a raw BPF is provided, it is used as-is; otherwise the Filter fields are concatenated.
func buildBPF(cfg Config) string {
	if cfg.BPFFilter != "" {
		return strings.TrimSpace(cfg.BPFFilter)
	}
	var b strings.Builder
	b.WriteString("tcp")
	f := cfg.UserFilter
	if f.SrcIP != "" {
		fmt.Fprintf(&b, " and src host %s", f.SrcIP)
	}
	if f.DstIP != "" {
		fmt.Fprintf(&b, " and dst host %s", f.DstIP)
	}
	if f.SrcPort > 0 {
		fmt.Fprintf(&b, " and src port %d", f.SrcPort)
	}
	if f.DstPort > 0 {
		fmt.Fprintf(&b, " and dst port %d", f.DstPort)
	}
	if f.Port > 0 {
		fmt.Fprintf(&b, " and port %d", f.Port)
	}
	return b.String()
}
