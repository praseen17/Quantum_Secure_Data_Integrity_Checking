# Research write-up

## Goal

This prototype explores an auditable workflow for sampled integrity checks of
erasure-coded data. It combines canonical serialization, SHA-256 Merkle
commitments, ML-DSA-signed manifests and receipts, uniform and risk-adaptive
sampling, authenticated selective repair, and an externally anchored receipt
log.

## Method

An owner encodes a file into supported Reed–Solomon shards, computes a Merkle
root over file/version/index-bound shard leaves, and signs a manifest. An
auditor issues a nonce-bound challenge; the cloud returns sampled shards and
proofs. The auditor verifies each response against the signed root and records
the result in signed receipts. Repair reconstructs an erased shard only from
authenticated same-stripe inputs and checks the reconstructed shard against
the original commitment before storage. Optional risk sampling supplements a
uniform baseline challenge.

## Evidence and interpretation

The unit and integration suite checks the specified serialization,
cryptographic binding, proof validation, erasure recovery, repair rejection,
challenge replay resistance, receipt chaining, and checkpoint comparisons.
These tests show behavior on covered inputs, not a formal proof.

Repeated benchmark studies cover 10 MB at 1%, 5%, and 10% sampling and 100 MB
at 5%, with localized and random fault schedules. Uniform and full Q-SAFE
detection-time bootstrap intervals overlap in all reported cells; the results
do not support a general risk-sampling advantage. The completed 500 MB result
is a scale smoke check only. Exact tables and measurement details are in
[BENCHMARK_REPORT.md](BENCHMARK_REPORT.md).

## Scope

The contribution is an integrated research prototype and reproducible test
harness. No novelty claim is made without a prior-art review. A sampled Merkle
audit is not a PDP/PoR proof, and use of ML-DSA does not establish end-to-end
quantum security. Assumptions and future work are listed in
[SECURITY_ASSUMPTIONS.md](SECURITY_ASSUMPTIONS.md) and [LIMITATIONS.md](LIMITATIONS.md).
