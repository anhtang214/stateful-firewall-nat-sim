# Integrated Network-Border Security Appliance

A simulated network security appliance in Python — a simplified combination firewall and intrusion detection system, built around four network zones (management, internal, DMZ, and external).

## Overview

The appliance accepts simulated IPv4 traffic over a custom packet capture format and, for each packet, either raises a security alert, forwards it toward the correct network zone, or silently drops it according to a defined security policy. It performs this entirely through raw byte and bit manipulation — there is no use of `scapy` or any external packet-handling library; Ethernet, IP, TCP, UDP, and ICMP headers are parsed and rebuilt by hand.

## Architecture

| Class | Responsibility |
|---|---|
| `Interface` | Represents one of the four NICs (`mgt`, `int`, `dmz`, `ext`) — MAC, IP, netmask, default route, and simulated packet transmission. |
| `InterfaceHandler` | Reads packets from the capture file and dispatches them to the correct interface. |
| `PacketEngine` | Core processing loop — parses each packet, applies the security policy, and routes or drops it. |
| `PatTable` | Port Address Translation (PAT) — maps internal/DMZ hosts to ephemeral external ports and reverses the mapping for return traffic. |
| `RouteTable` | Resolves the correct egress interface for a destination IP using longest-prefix matching, falling back to the external interface. |
| `Connections` | Tracks connection state (`new`, `syn_sent`, `established`) per interface/protocol/address/port tuple, so only legitimately initiated connections can receive return traffic. |

## Core Features

- **Raw protocol parsing** — Ethernet, IP, TCP, UDP, and ICMP headers parsed directly from bytes/bits, with no external packet libraries.
- **Stateful firewall** — tracks TCP connection state so return traffic is only permitted for connections that were actually initiated.
- **NAT/PAT** — hides internal and DMZ addressing behind the appliance's external interface on dynamically allocated ephemeral ports, with correct reverse translation for replies.
- **Zone-based security policy** — including restricted SSH access to the management interface, DNS and HTTP/HTTPS handling across zones, and routing of inbound traffic to DMZ proxies (web server and SSH jump box).
- **ICMP abuse protection** — rejects oversized pings, rate-limits repeated ping requests, and blocks disallowed ICMP types.
- **Flood protection** — clears all partial connections if incomplete connection requests exceed a defined threshold.

## How It Works

1. `InterfaceHandler` reads simulated packets from `traffic.spcap`.
2. Each packet is passed to `PacketEngine.process_packet`, which parses it and applies `check_packet`'s security logic.
3. Depending on the result, the engine either prints a security alert, performs NAT/PAT translation and rewrites the packet, or routes it via `RouteTable.resolve` to the correct interface.
4. `route_packet` simulates sending the (possibly rewritten) packet out through the resolved `Interface`.

## Running It

```bash
python3 appliance.py
```

Reads `traffic.spcap` from the same directory and prints NAT allocations, security alerts, and routing decisions to stdout.

## Sample Files

- `traffic.spcap` — a sample simulated packet capture
- `sample_output.txt` — the expected output for that sample capture

## Tech

Python 3.13, standard library only — no external packet-parsing libraries.
