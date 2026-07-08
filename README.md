# tcpcap

> English | [中文](README_zh-CN.md)

A lightweight TCP packet capture tool written in Go. It works like `tcpdump` but **focuses on TCP** and outputs **structured JSON / text**, exposing TCP-specific fields (seq, ack, flags, window) in a parseable form — making it easy for other programs (log collectors, data analytics, Python scripts, SIEM, etc.) to consume directly, and solving the problem that tcpdump's text output is hard to parse programmatically.

It is built on [gopacket](https://github.com/google/gopacket) + libpcap (Npcap on Windows), the same lineage as tcpdump. Filtering is done in **kernel-space BPF** for high efficiency.

A UDP-focused sibling, [`udpcap`](https://github.com/fetaoily/udpcap), uses the same design.

---

## Features

- 🎯 **TCP-focused**: captures only TCP. Filter conditions (port/IP) are auto-converted to BPF for kernel-space filtering.
- 📊 **TCP state fields**: each segment exposes `seq`, `ack`, `flags` (e.g. `SYN,ACK`), `data_offset`, and `window` in a structured way — great for connection/flow analysis.
- 📦 **Structured output**:
  - `jsonl` (default, JSON Lines): one JSON object per line, streamed — best for real-time pipe parsing
  - `json`: a complete JSON array, for offline batch processing
  - `text`: human-readable text (tcpdump-like)
- 🔎 **Custom BPF**: same syntax as tcpdump (`-bpf "tcp port 443"`)
- 📝 **Optional payload**: `-no-payload` for metadata only; `-max-payload` to limit payload length
- ⏱️ **Nanosecond timestamps**: provides both RFC3339 time and Unix nanosecond timestamps
- 🪟 **Cross-platform**: Windows / Linux / macOS

---

## Output Formats

### JSON Lines (default, `-f jsonl`)

One independent JSON object per line, parseable line-by-line with `jq` or Python `json.loads`:

```json
{"timestamp":"2026-07-08T14:30:00.123456789Z","timestamp_unix_nano":1752014600123456789,"interface":"eth0","ip_version":4,"src_ip":"192.168.1.5","dst_ip":"93.184.216.34","src_port":51234,"dst_port":80,"seq":1,"ack":1,"flags":"PSH,ACK","data_offset":32,"window":64240,"length":117,"payload_size":85,"payload_hex":"474554202f...","payload_text":"GET / HTTP..."}
```

Field reference:

| Field | Type | Description |
| ------ | ------ | ------ |
| `timestamp` | string | RFC3339 nanosecond timestamp |
| `timestamp_unix_nano` | int64 | Unix nanosecond timestamp |
| `interface` | string | capture interface |
| `ip_version` | int | IP version (4 or 6) |
| `src_ip` / `dst_ip` | string | source / destination IP |
| `src_port` / `dst_port` | int | source / destination port |
| `seq` | uint32 | sequence number |
| `ack` | uint32 | acknowledgment number |
| `flags` | string | TCP flags, e.g. `SYN,ACK`, `PSH`, `FIN`, `NONE` |
| `data_offset` | int | TCP header length in bytes |
| `window` | int | receive window size |
| `length` | int | total segment length (header + payload) |
| `payload_size` | int | payload size in bytes |
| `payload_hex` | string | hex representation of the payload |
| `payload_text` | string | printable payload (non-printable bytes replaced with `.`) |

### Text (`-f text`)

```text
14:30:00.123456 IPv4 192.168.1.5:51234 > 93.184.216.34:80 [PSH,ACK] seq=1 ack=1 win=64240 len=117 payload=85 | 474554202f...
```

---

## Requirements

Capturing depends on libpcap; installation differs per platform:

### Windows (required)

1. **Install Npcap** (runtime capture driver): <https://npcap.com/dist/>
   - During installation, check **"Install Npcap in WinPcap API-compatible Mode"**
2. **Install the Npcap SDK** (for building): <https://npcap.com/dist/> → download `npcap-sdk-*.zip`
   - Extract it to e.g. `C:\npcap-sdk`
3. **Install a C compiler** (cgo requires one) — [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or MSYS2's mingw-w64 is recommended
4. Set environment variables:

   ```bat
   set CGO_ENABLED=1
   set CPATH=C:\npcap-sdk\Include;%CPATH%
   set LIBRARY_PATH=C:\npcap-sdk\Lib\x64;%LIBRARY_PATH%
   ```

   > At runtime you also need to add `C:\Windows\System32\Npcap` to `PATH`, or ship `wpcap.dll` / `Packet.dll` alongside the binary.

### Linux

```bash
sudo apt install libpcap-dev     # Debian/Ubuntu
sudo yum install libpcap-devel   # CentOS/RHEL
```

### macOS

libpcap is bundled with the system; no extra install needed.

---

## Build

```bash
cd tcpcap
go mod tidy
go build -o tcpcap .
```

For a ready-made cross-platform build script (produces a fully static Linux binary via Docker), see [`build.sh`](build.sh).

---

## Usage

### 1. List available network interfaces

```bash
./tcpcap --list-interfaces
```

```text
Interface (-i)                                  Description / Addresses
----------------------------------------------------------------------------------------------------
eth0                                             Realtek PCIe GbE (192.168.1.5, fe80::1)
```

### 2. Capture all TCP packets (default: JSON Lines to stdout)

```bash
./tcpcap -i eth0
```

### 3. Filter by port (e.g. HTTP)

```bash
./tcpcap -i eth0 -p 80
```

### 4. Write to a file

```bash
./tcpcap -i eth0 -o http.jsonl -p 80
```

### 5. Text format (human-readable, with TCP flags/seq/ack)

```bash
./tcpcap -i eth0 -f text
```

### 6. Custom BPF (same syntax as tcpdump)

```bash
./tcpcap -i eth0 -bpf "tcp port 443 or tcp port 22"
```

### 7. Pipe to other tools (e.g. summarize TCP flags)

```bash
./tcpcap -i eth0 -p 80 | jq -r '.flags' | sort | uniq -c
```

---

## Options

| Flag | Default | Description |
| ------ | -------- | ------ |
| `-i` | (required) | network interface name |
| `--list-interfaces` | - | list all interfaces and exit |
| `-f` | `jsonl` | output format: `jsonl` / `json` / `text` |
| `-o` | (stdout) | output file path |
| `-p` | 0 | filter by port (source or destination) |
| `--src-port` / `--dst-port` | 0 | filter by source / destination port |
| `--src-ip` / `--dst-ip` | (empty) | filter by source / destination IP |
| `-bpf` | (empty) | raw BPF expression (overrides the filters above when set) |
| `--no-payload` | false | do not output payload content |
| `--max-payload` | 256 | max payload bytes to display (0 = unlimited) |
| `--snaplen` | 65536 | snapshot length |
| `--promisc` | false | enable promiscuous mode |
| `--timeout` | 0 | read timeout in seconds (0 = block forever) |

> 💡 On most systems, capturing requires **administrator/root privileges**.

---

## Project Structure

```text
tcpcap/
├── go.mod
├── main.go                  # CLI entry point
├── build.sh                 # cross-platform build script
├── internal/
│   ├── capture/capture.go   # capture core (BPF kernel filtering)
│   ├── packet/packet.go     # structured TCP packet definition
│   └── output/output.go     # output formatting (JSON Lines / JSON / Text)
└── README.md
```
