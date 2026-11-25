# Changelog

All important changes to `dvpn-sim` are recorded here.

## [Unreleased]

### Planned
- Real onion cells (layered encryption, fixed-size cells) instead of the current "next-hop only" abstraction.
- DNS flow through the circuit + direct-DNS leak detection.
- Adjacent-hop cross-signed receipts (currently each hop signs its own receipt).
- Random data challenge (probabilistic proof of relay), not just counter comparison.
- E+X traffic-correlation experiment and 2/3/4-hop comparison.
- Padding / batching experiment.

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

### Known limitations
- Onion routing is still an abstraction (each hop only sees the next hop; no real layered cells).
- Receipts are single-signed per hop, not cross-signed by adjacent hops.
- Audit compares counters; it does not yet challenge specific data blocks.
- No DNS flow, padding, E+X correlation, stake ledger, or settlement.
- Signatures are generated but not yet verified during audit.
