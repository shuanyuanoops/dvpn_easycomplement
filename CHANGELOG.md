# Changelog

All important changes to `dvpn-sim` are recorded here.

## [Unreleased]

### Planned
- Adjacent-hop cross-signed receipts (currently each hop signs its own receipt).
- Random data challenge (probabilistic proof of relay), not just counter comparison.
- E+X traffic-correlation experiment and 2/3/4-hop comparison.
- Padding / batching experiment.
- Stake ledger and settlement (currently only slash counters).

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
