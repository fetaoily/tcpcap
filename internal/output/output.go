// Package output provides multiple output formats for packets:
//   - jsonl (JSON Lines): one JSON object per line, streamed, best for real-time parsing (default)
//   - json: a full JSON array, closed at the end, suitable for offline batch processing
//   - text: human-readable lines (tcpdump-like)
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/fetaoily/tcpcap/internal/packet"
)

// Writer is the packet output interface.
type Writer interface {
	Write(p *packet.TCPPacket) error
	Close() error
}

// NewWriter creates a Writer for the given format.
func NewWriter(format string, w io.Writer) (Writer, error) {
	switch format {
	case "", "jsonl", "ndjson":
		return NewJSONLinesWriter(w), nil
	case "json":
		return NewJSONArrayWriter(w), nil
	case "text":
		return NewTextWriter(w), nil
	default:
		return nil, fmt.Errorf("unknown output format %q (valid: jsonl, json, text)", format)
	}
}

// ---- JSON Lines ----

// JSONLinesWriter writes one JSON object per line, suitable for streaming and piping.
type JSONLinesWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONLinesWriter creates a JSON Lines writer.
func NewJSONLinesWriter(w io.Writer) *JSONLinesWriter {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // payload may contain arbitrary bytes; disable HTML escaping for easier parsing
	return &JSONLinesWriter{enc: enc}
}

// Write writes one packet.
func (j *JSONLinesWriter) Write(p *packet.TCPPacket) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.enc.Encode(p) // Encode appends a trailing newline
}

// Close closes the writer (JSON Lines needs no finalization).
func (j *JSONLinesWriter) Close() error { return nil }

// ---- JSON array ----

// JSONArrayWriter writes a complete JSON array, closed by Close.
// Note: it accumulates over time; suitable for bounded-duration captures.
type JSONArrayWriter struct {
	mu     sync.Mutex
	w      io.Writer
	enc    *json.Encoder
	first  bool
	closed bool
}

// NewJSONArrayWriter creates a JSON array writer and writes the opening bracket.
func NewJSONArrayWriter(w io.Writer) *JSONArrayWriter {
	fmt.Fprint(w, "[\n")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return &JSONArrayWriter{w: w, enc: enc, first: true}
}

// Write writes one packet.
func (j *JSONArrayWriter) Write(p *packet.TCPPacket) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return fmt.Errorf("writer is closed")
	}
	if !j.first {
		fmt.Fprint(j.w, ",\n")
	}
	j.first = false
	return j.enc.Encode(p)
}

// Close writes the closing bracket.
func (j *JSONArrayWriter) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	_, err := fmt.Fprint(j.w, "\n]\n")
	return err
}

// ---- Text ----

// TextWriter writes human-readable lines (tcpdump-like).
type TextWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewTextWriter creates a text writer.
func NewTextWriter(w io.Writer) *TextWriter {
	return &TextWriter{w: w}
}

// Write writes one packet.
func (t *TextWriter) Write(p *packet.TCPPacket) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, err := fmt.Fprintf(t.w,
		"%s IPv%d %s:%d > %s:%d [%s] seq=%d ack=%d win=%d len=%d payload=%d",
		p.Timestamp.Format("15:04:05.000000"),
		p.IPVersion,
		p.SrcIP, p.SrcPort,
		p.DstIP, p.DstPort,
		p.Flags,
		p.Seq, p.Ack, p.Window, p.Length, p.PayloadSize,
	)
	if err != nil {
		return err
	}
	if p.PayloadHex != "" {
		if _, err := fmt.Fprintf(t.w, " | %s", p.PayloadHex); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(t.w)
	return err
}

// Close closes the writer (text needs no finalization).
func (t *TextWriter) Close() error { return nil }
