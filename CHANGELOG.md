# Changelog

All important changes to `dvpn-sim` are recorded here.

## [Unreleased]

### Planned
- Adjacent-hop cross-signed receipts (currently each hop signs its own receipt).
- Random data challenge (probabilistic proof of relay), not just counter comparison.
- E+X traffic-correlation experiment and 2/3/4-hop comparison.
- Padding / batching experiment.
- Stake ledger and settlement (currently only slash counters).

## [0.6.0] - 2026-11-25

### Added
- Tests for relay circuit state, audit chain, and X25519 handshake.
- X25519 handshake: relay static keypair (`-pubkey-out`), client seals a fresh
  32-byte session key per hop (`-pub-*`), relays install keys by local tag.
  No more command-line pre-shared AES keys.
- Handshake frames are tag-rewritten like data frames; data looks up the
  session key by local tag.

### Measured
- 4000/4000 replies, 0% loss, RTT min 23 us / avg 124 us / max 777 us.
- Forward audit: 0.0000% mismatch at every hop.
- Each relay saw exactly 1 handshake.

## [0.5.1] - 2026-11-25

### Changed
- Reverse path now uses per-hop tag rewriting instead of one global circuit id.
  Each relay sees only its local in/out tags:
  `t0 -> t1 -> t2`, and reply rewrites `t2 -> t1 -> t0`.
- Relay state is O(active circuits): `in[tag] -> {prev, outTag}` and
  `out[outTag] -> inTag`.

### Measured
- 4000/4000 replies, 0% loss, RTT min 23 us / avg 121 us / max 798 us.
- Forward audit: 0.0000% mismatch at every hop.

### Known limitations
- No tag expiry / idle cleanup yet.
- Reply is not onion-encrypted.
- One client per circuit.

## [0.5.0] - 2026-11-25

### Added
- Reverse path: forward frames carry an 8-byte circuit id; each relay keeps a
  `circuit -> previous peer` table; reply frames are forwarded by lookup only.
- Client-side reply listener and RTT measurement.
- Reply counters separated from forward counters, so the forward byte chain
  audit stays exact.

### Measured
- 4000/4000 replies, 0% loss, RTT min 21 us / avg 132 us / max 927 us (localhost).
- Forward audit: 0.0000% mismatch at every hop.

### Known limitations
- Circuit id is visible to all relays (linkability); reverse reply is not onion-encrypted.
- One client per circuit.

## [0.4.0] - 2026-11-25

### Added
- `docs/ENGINEERING.md`: architecture, data plane, privacy, metering, failure modes,
  and the "harder but not implemented" list.
- Signed receipts on the real UDP transport: relay/client/sink write Ed25519 receipts.
- `cmd/audit` verifies signatures and checks the byte-count chain
  (client -> entry -> middle -> exit -> sink).

### Measured
- 4000 cells, 3.56 MB payload, 4.096 MB wire.
- Audit chain mismatch: 0.0000% at every hop.

## [0.3.0] - 2026-11-25

### Added
- Real local UDP 3-hop transport: `cmd/relay` (entry/middle/exit), `cmd/client`,
  `cmd/sink`.
- Fixed 1024-byte wire frame: `[2-byte length][inner cell][zero padding]`.
  Each relay peels one onion layer and re-frames, so the wire size stays 1024 B.
- `scripts/run_local.sh` end-to-end demo.
- `internal/frame` with round-trip and oversize tests.
- Measured on localhost: 4000 cells, 3.56 MB payload, 4.096 MB wire,
  avg one-way latency ~122 us, ~3784 pps (client pacing limited).

### Known limitations
- One-way only; no reverse path / RTT yet.
- Keys are pre-shared via flags; no handshake.
- Metering/audit is still in the simulator, not yet wired into the UDP transport.

## [0.2.0] - 2026-11-25

### Added
- Real onion cells: AES-256-GCM layers, 16-byte next-hop field, fixed 1024-byte cell.
  - 3-hop payload capacity: 892 bytes (`1024 - 3 * 44`).
- Per-hop peel: each hop decrypts one layer and learns only the next hop.
- DNS mode:
  - `-dns tunnel`: a DNS packet goes through the circuit; counted as `dns_packets`.
  - `-dns local`: no DNS packet; `local_dns_leaks` increments (models the client's
    local resolver leaking the domain).
- Payload vs wire accounting (`payload_mb`, `wire_mb`); cell overhead is visible.
- Onion tests: build/peel 3 hops, tamper detection.

### Changed
- `Packet` now carries `Cell`, `PayloadSize`, `Kind`.
- `PacketSize` replaced by `CellSize` (1024) and `DNSSize` (200).
- Throughput now reflects cell padding (≈14 MB/s vs 19 MB/s in v0.1.0).

### Known limitations
- Circuit keys are pre-shared by the simulator; no X25519 circuit setup yet.
- Receipts are single-signed per hop, not cross-signed by adjacent hops.
- Audit compares counters; it does not yet challenge specific data blocks.
- No E+X correlation, padding, stake ledger or settlement.

## [0.1.0] - 2026-11-25

### Added
- Go module `dvpn-sim`, standard library only.
- 3-hop event-driven simulation: `client -> entry -> middle -> exit -> destination`.
- Per-link latency, serialization delay and simple queueing (`nextFree`).
- Per-hop byte counters and Ed25519-signed receipts with a SHA-256 hash chain.
- Audit using the median of client + E/M/X counters to find a single outlier:
  - node over-report -> slash node stake;
  - client under-report -> flag client, do not slash nodes.
- Scenarios: `honest`, `overreport`, `underreport`.
- Go tests: honest no-flag, over-report detected, under-report flags client only.
- CLI prints a 3-hop knowledge matrix.
