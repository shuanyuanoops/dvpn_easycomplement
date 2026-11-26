# Changelog

All important changes to `dvpn-sim` are recorded here.

## [Unreleased]

### Planned
- Adjacent-hop cross-signed receipts (currently each hop signs its own receipt).
- Random data challenge (probabilistic proof of relay), not just counter comparison.
- E+X traffic-correlation experiment and 2/3/4-hop comparison.
- Padding / batching experiment.
- Stake ledger and settlement (currently only slash counters).

## [0.14.0] - 2026-11-26

### Added
- Frame header now carries an 8-byte sequence; relay rejects duplicate/old seq.
- X25519 identity documents: Ed25519 identity signs the X25519 key; client
  verifies before sealing.
- Handshake ACK: exit returns an encrypted ACK; client retries 3x/300ms.
- Reply encryption: exit holds a reply key from the handshake; replies are
  AES-GCM encrypted instead of plaintext.
- Link receipts now carry separate `Sent*` / `Recv*` counts signed by each side.
- Tests: frame seq, identity sign/verify/tamper, payload seal/open, link receipt.

### Measured
- 4000/4000 replies, 0% loss, RTT avg ~130-140 us, audit 0.0000%.
- Handshake ACK received once per relay; encrypted replies verified by client.

## [0.13.0] - 2026-11-25

### Added
- Per-link packet loss and duplication in the simulator (`-loss`, `-dup`).
- Tolerance-based link slashing: `sent` vs `recv` with 3-sigma loss/dup bounds
  and slack; slash sender below min, receiver above max.
- Median counter audit is disabled when loss/dup > 0 to avoid false positives.
- Tests: honest 10%/10% loss/dup -> 0 link failures, 0 slash; overreport 1.5x
  under 10%/10% -> link failures + slash.

### Measured (40 clients x 20 packets, 10% loss / 10% dup)
- honest: dropped=264 duplicated=214, link_failed=0, slashed=0.
- overreport entry-0: link_failed=7, slashed=70, detected 7/17 cheat sessions.

## [0.12.0] - 2026-11-25

### Added
- `internal/merkle`: Merkle tree build, proof, verify; tests for 1/2/3/5/8 leaves.
- Chain settlement now stores the receipt Merkle root; dispute verifies
  `leaf + index + proof` before slashing.
- `internal/chain` tests updated for valid/invalid proofs.
- Tag idle timeout in `internal/circuit` (`Cleanup`), relay `-tag-ttl` with a
  one-minute cleanup goroutine; expiry test.
- `cmd/chain` demo now settles with a Merkle root and disputes with a proof.

## [0.11.0] - 2026-11-25

### Added
- `internal/chain`: simulated ledger with Ed25519-signed txs for node
  registration, stake/unstake, deposit, epoch settlement, and dispute/slash.
- Blocks with prev-hash chaining; account balances, node stake/earned, treasury.
- `cmd/chain` demo: register 3 nodes, settle epoch 1, dispute exit, print state.
- `docs/ENGINEERING.md` §7.6: on-chain vs off-chain table.
- Tests: register/stake/settle, dispute slash, bad signature, block chain.

## [0.10.0] - 2026-11-25

### Added
- Random hop range: `HopsMin` / `HopsMax` (default 3..3, max 5); each session
  picks its own length.
- `AvgHops` and `DistinctCircuits` metrics; test for random hops + diversity.
- `cmd/bench`: 4 hop counts x 3 cell sizes x 2 cover settings, writes
  `results/bench.csv` and prints a Markdown table.
- `STATUS.md`: feature/test/limit matrix.

### Measured (40 clients x 20 packets, DNS local)
- 2/3/4/5 hops at 1024 B: 60/80/100/120 ms, 6.34/5.17/4.29/3.61 MB/s.
- cell 512/1024/1500 at 3 hops: 2.20/5.17/7.93 MB/s.
- cover 0 -> 100 at 3 hops/1024: anon 18.25 -> 25.52, link 0.06 -> 0.04.

## [0.9.0] - 2026-11-25

### Added
- `internal/privacy`: E+X collusion analysis over `(start, bytes)` observations,
  with synthetic cover sessions.
- `-cover N` CLI flag; `anonymity_set` and `linkability` metrics.
- Tests for privacy analysis and sim integration.

### Measured (20 clients x 20 packets, DNS local)
- cover=0:   anonymity_set=15.50, linkability=0.07
- cover=100: anonymity_set=21.05, linkability=0.05

## [0.8.0] - 2026-11-25

### Added
- `Config.Hops` (2/3/4) and general circuit path builder.
- `-hops` and `-cell` CLI flags.
- `TestHops234`.

### Measured (20 clients x 20 packets, DNS local)
- hops: 2 -> 60 ms / 3.82 MB/s; 3 -> 80 ms / 3.02 MB/s; 4 -> 100 ms / 2.46 MB/s.
- cell: 512 -> 1.29 MB/s; 1024 -> 3.02 MB/s; 1500 -> 4.64 MB/s.

## [0.7.0] - 2026-11-25

### Added
- Cross-signed link receipts: E-M and M-X each carry Ed25519 signatures from both
  endpoints over `session|from|to|seqStart|seqEnd|bytes`.
- Audit verifies both signatures and compares the sender's bytes with the
  receiver's counter.
- Per-packet evidence hashes and random challenge: each hop stores
  `H(session|seq|bytes)`; audit samples 3 seqs per session.
- Tests for `internal/link` and integration tests in `internal/sim`.

### Measured
- honest: 120 link receipts, 0 failed; 540 challenges, 0 failed.
- overreport: 22 link receipts failed (the sessions containing entry-0).
- underreport: 0 link failures; client flagged by the counter audit.

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
