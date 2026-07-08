// Package packet defines the structured representation of a TCP packet.
//
// TCPPacket is an intermediate representation that can be serialized to
// JSON / text etc., making it easy for other programs (log collectors,
// data analytics, SIEM, Python scripts) to parse directly. Compared to
// raw tcpdump text, it exposes TCP-specific fields (seq, ack, flags,
// window) in a structured way.
package packet

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPPacket is the structured representation of a TCP segment.
type TCPPacket struct {
	// Timestamp
	Timestamp time.Time `json:"timestamp"`           // RFC3339 with nanoseconds
	UnixNano  int64     `json:"timestamp_unix_nano"` // Unix nanosecond timestamp

	// Capture interface
	Interface string `json:"interface,omitempty"`

	// IP layer
	IPVersion int    `json:"ip_version"` // 4 or 6
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`

	// TCP layer
	SrcPort    int    `json:"src_port"`
	DstPort    int    `json:"dst_port"`
	Seq        uint32 `json:"seq"`         // sequence number
	Ack        uint32 `json:"ack"`         // acknowledgment number
	Flags      string `json:"flags"`       // e.g. "SYN,ACK", "PSH", "FIN", "NONE"
	DataOffset int    `json:"data_offset"` // TCP header length in bytes
	Window     int    `json:"window"`      // receive window size
	Length     int    `json:"length"`      // total segment length (header + payload)

	// Payload
	PayloadSize int    `json:"payload_size"`           // payload size in bytes
	PayloadHex  string `json:"payload_hex,omitempty"`  // hex representation of the payload
	PayloadText string `json:"payload_text,omitempty"` // printable representation (non-printable bytes replaced with .)
}

// FromPacket parses a gopacket.Packet into a TCPPacket.
// Returns nil if the packet does not contain a TCP layer.
//
// includePayload controls whether PayloadHex / PayloadText are populated.
// maxPayload limits the number of payload bytes shown; <= 0 means unlimited.
func FromPacket(pkt gopacket.Packet, iface string, includePayload bool, maxPayload int) *TCPPacket {
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return nil
	}

	meta := pkt.Metadata()
	out := &TCPPacket{
		Timestamp:  meta.Timestamp,
		UnixNano:   meta.Timestamp.UnixNano(),
		Interface:  iface,
		SrcPort:    int(tcp.SrcPort),
		DstPort:    int(tcp.DstPort),
		Seq:        tcp.Seq,
		Ack:        tcp.Ack,
		Flags:      tcpFlags(tcp),
		DataOffset: int(tcp.DataOffset) * 4,
		Window:     int(tcp.Window),
		Length:     int(tcp.DataOffset)*4 + len(tcp.Payload),
	}

	// Parse the network layer (IP)
	switch l := pkt.NetworkLayer().(type) {
	case *layers.IPv4:
		out.IPVersion = 4
		out.SrcIP = l.SrcIP.String()
		out.DstIP = l.DstIP.String()
	case *layers.IPv6:
		out.IPVersion = 6
		out.SrcIP = l.SrcIP.String()
		out.DstIP = l.DstIP.String()
	default:
		// Fallback: extract from the network flow endpoints
		if nl := pkt.NetworkLayer(); nl != nil {
			src, dst := nl.NetworkFlow().Endpoints()
			out.SrcIP = src.String()
			out.DstIP = dst.String()
		}
	}

	payload := tcp.Payload
	out.PayloadSize = len(payload)
	if includePayload && len(payload) > 0 {
		n := len(payload)
		if maxPayload > 0 && n > maxPayload {
			n = maxPayload
		}
		out.PayloadHex = hex.EncodeToString(payload[:n])
		out.PayloadText = toPrintable(payload[:n])
	}

	return out
}

// tcpFlags builds a readable, ordered flag string like "SYN,ACK" or "PSH".
// Returns "NONE" when no flags are set.
func tcpFlags(tcp *layers.TCP) string {
	var f []string
	if tcp.FIN {
		f = append(f, "FIN")
	}
	if tcp.SYN {
		f = append(f, "SYN")
	}
	if tcp.RST {
		f = append(f, "RST")
	}
	if tcp.PSH {
		f = append(f, "PSH")
	}
	if tcp.ACK {
		f = append(f, "ACK")
	}
	if tcp.URG {
		f = append(f, "URG")
	}
	if tcp.ECE {
		f = append(f, "ECE")
	}
	if tcp.CWR {
		f = append(f, "CWR")
	}
	if tcp.NS {
		f = append(f, "NS")
	}
	if len(f) == 0 {
		return "NONE"
	}
	return strings.Join(f, ",")
}

// toPrintable converts a byte slice to a printable string, replacing
// non-printable bytes (< 0x20 or >= 0x7f) with '.'.
func toPrintable(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
