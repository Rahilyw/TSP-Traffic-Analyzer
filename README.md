# TCP Traffic Analyzer

A pure-Python engine that reconstructs TCP connection state machines and extracts performance metrics from raw `.cap` packet captures — zero external dependencies.

## Why This Exists

Most network analysis tools hand you an abstraction layer. This tool parses every connection from the ground up: raw binary, byte by byte — Ethernet frame → IP header → TCP segment — without scapy, dpkt, or any other library. The goal was to understand TCP at the protocol level, not to call a function that already understands it for you.

## What It Does

Feed it a `.cap` file. Get back a full audit of every TCP connection in the trace.

```
$ python3 tcp_analyzer.py sample-capture-file.cap

A) Total number of connections: 48
____________________________________________________________________________________________

B) Connections' details:

Connection 2:
Source Address: 192.168.1.164
Destination address: 142.104.5.64
Source Port: 1201
Destination Port: 80
Status: S2F2
Duration: 24.122220
Start time: 1139256720.503946
End Time: 1139256744.626166
Number of packets sent from Source to Destination: 28
Number of packets sent from Destination to Source: 41
Total number of packets: 69
Number of data bytes sent from Source to Destination: 1334
Number of data bytes sent from Destination to Source: 52974
Total number of data bytes: 54308
END
...
____________________________________________________________________________________________

C) General

The total number of complete TCP connections: 32
The number of reset TCP connections: 34
The number of TCP connections that were still open when the trace capture ended: 32
The number of TCP connections established before the capture started: 0
____________________________________________________________________________________________

D) Complete TCP connections:

Minimum time duration: 0.014006 seconds
Mean time duration: 7.191411 seconds
Maximum time duration: 45.054007 seconds

Minimum RTT value: 0.002269
Mean RTT value: 0.039433
Maximum RTT value: 0.159684

Minimum number of packets including both send/received: 8
Mean number of packets including both send/received: 37.312500
Maximum number of packets including both send/received: 239

Minimum receive window size including both send/received: 0
Mean receive window size including both send/received: 15277.688442
Maximum receive window size including both send/received: 64240
____________________________________________________________________________________________
```

## Engineering Highlights

### 1. Zero-Dependency Binary Parsing

The pcap file format has no self-describing schema. This analyzer manually unpacks every layer:

- **pcap Global Header** → magic number detection (`0xA1B2C3D4` = little-endian, `0xD4C3B2A1` = big-endian)
- **pcap Packet Record** → timestamp reassembly from `ts_sec + ts_usec`, byte order applied from magic
- **Ethernet II Frame** → EtherType filtering for IPv4 (`0x0800`)
- **IPv4 Header** → IHL-based header length calculation, protocol filtering for TCP (`0x06`), source/destination extraction
- **TCP Header** → Data Offset field for payload boundary, flag bitmask extraction (`SYN=0x02`, `FIN=0x01`, `RST=0x04`, `ACK=0x10`)

All unpacking done using only Python's standard library — `struct` for binary unpacking, `socket` for IP address formatting, `sys` for CLI argument handling. No `pip install` required, ever.

### 2. TCP State Machine

Each connection is tracked through a custom state model based on SYN/FIN counts in both directions:

| State  | Meaning                                          |
|--------|--------------------------------------------------|
| S0F0   | No SYN, No FIN seen                              |
| S1F0   | One SYN (initial), no FIN                        |
| S2F0   | Full handshake (SYN + SYN-ACK), no FIN          |
| S2F2   | Complete open and close                          |
| R      | Connection reset mid-stream                      |
| ...    | And all intermediate states                      |

A SYN-ACK segment (both bits set) is counted as a SYN — consistent with how TCP implementations count it in the handshake. This distinction matters for correctly classifying connections that appear mid-trace.

### 3. Packet Interleaving & 4-Tuple Demultiplexing

Packets from dozens of concurrent connections arrive in arbitrary temporal order. Every packet is routed to the correct connection via a normalized 4-tuple key:

```python
connection_id = tuple(sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"]))
```

The normalization is direction-agnostic — `(A:p1, B:p2)` and `(B:p2, A:p1)` resolve to the same connection — ensuring duplex flows are correctly unified.

### 4. RTT Estimation

RTT is computed from SYN → SYN-ACK timing on complete connections. This is the same method used by the Linux kernel's initial RTT estimate before retransmission data is available.

### 5. Edge Case Handling

Real packet captures are messy. This analyzer handles:

- **Pre-capture connections** — first segment is not SYN → flagged as established before trace started
- **Connections open at trace end** — no FIN seen, or data segments arrive after the last FIN → marked as open
- **Mid-stream resets** — RST flag triggers immediate state transition to `R`
- **Half-open connections** — only one side of the handshake visible in the trace

## Architecture

```
tcp_analyzer.py
│
├── _parse_ethernet(packet_data)          # EtherType extraction + IPv4 filter
├── _parse_ipv4(packet_data, offset)      # IHL, protocol, src/dst IPs
├── _parse_tcp(packet_data, offset)       # Ports, seq/ack, flags, window size
│
├── analyze_tcp_traffic(pcap_filepath)    # Orchestration: parse → demux → state
│   ├── pcap global header → magic number byte-order detection
│   ├── Per-packet: _parse_ethernet → _parse_ipv4 → _parse_tcp
│   ├── 4-tuple demultiplexing → normalized connection_id key
│   ├── Connection state machine (SYN/FIN/RST counts, edge case detection)
│   ├── Directional packet + byte accounting
│   └── RTT estimation (unacked_packets_A_to_B dict, SYN→ACK timing)
│
└── gen_formatted_output(connections)     # Sections A–D report
    ├── Section A: total connection count
    ├── Section B: per-connection detail (state-gated fields)
    ├── Section C: aggregate counts (complete/reset/open/pre-capture)
    └── Section D: min/mean/max for duration, RTT, packets, window
```

## Usage

**Requirements:** Python 3.8+ (no pip installs needed)

```bash
# Run analysis
python3 tcp_analyzer.py <capture_file.cap>

# Example
python3 tcp_analyzer.py sample-capture-file.cap
```

The analyzer runs on any system with Python 3.8+ and is tested on Linux (linux.csc.uvic.ca).

## What I Learned

Building this without any networking libraries forced a genuine understanding of protocol layering that using scapy would have hidden:

- **pcap is a simple sequential binary format** — there's no index, no seekable structure. You parse it linearly, and byte order isn't guaranteed, so the magic number check is load-bearing, not cosmetic.
- **TCP's "state" in the real world is messier than the textbook diagram.** Connections appear mid-stream, reset unexpectedly, and overlap in ways that require careful bookkeeping.
- **RTT estimation from a passive trace (rather than an active probe) is inherently approximate** — you're inferring timing from when packets were captured, not when they were received by the host.
- **Window size as reported is not the effective window** — the actual receive window is `window_size << window_scale_factor` once TCP window scaling (RFC 1323) options are negotiated. This implementation reads the raw field; a production tool would parse the TCP Options to apply the scale factor.

## Skills Demonstrated

Python · Binary Protocol Parsing · TCP/IP Internals · State Machine Design · Network Diagnostics · Systems Programming · Data Analysis

## Context

Built as part of **CSc 361: Computer Communications and Networks** at the University of Victoria (Spring 2026).

⚠️ Academic Integrity Notice

- This repository is maintained for portfolio and educational purposes only. If you are currently enrolled in CSc 361 at the University of Victoria or a similar Networks course, please note that using this code in your own assignments may constitute a violation of Academic Integrity policies.
---
