# Architecture

Q-SAFE is a C++17 research prototype for checking sampled data shards in a
simulated cloud. Its libraries follow the data path:

1. `storage` splits files into fixed-size chunks and persists shards and proof
   metadata in a local SQLite-backed store.
2. `repair` encodes supported 4+2 and 6+3 layouts using ISA-L.
3. `crypto` hashes canonical values with SHA-256 and signs manifests and audit
   receipts with ML-DSA through liboqs.
4. `manifest` binds file identity, version, shard layout, and Merkle root.
5. `merkle` builds domain-separated trees and index-aware inclusion proofs.
6. `audit` creates nonce-bound uniform challenges, verifies sampled responses,
   estimates uniform detection probabilities, and adds optional risk samples.
7. `repair` reconstructs an erased shard from authenticated same-stripe inputs,
   verifies it against the original root, stores it, and performs a targeted
   re-audit.
8. `receipts` signs audit outcomes and stores them in a SQLite hash chain,
   checked against a separately held checkpoint.

`qsafe_vault` and the browser interface support persistent local user-file
ingest, sampled integrity audits, missing/corrupt shard repair, and verified
file restoration. `qsafe_demo` exercises signed receipts and checkpoint
verification. The benchmark executable compares uniform, repair, diagnostic
risk-only, and full Q-SAFE paths. See [THREAT_MODEL.md](THREAT_MODEL.md) and
[SECURITY_ASSUMPTIONS.md](SECURITY_ASSUMPTIONS.md) before interpreting results.

## Trust and data flow

The owner signing key authenticates the manifest. The auditor key independently
authenticates receipts. Verifiers receive trusted public keys out of band; a
public key supplied by the cloud is not trusted. The checkpoint must be kept
outside the SQLite log's rollback domain. The local simulated cloud and its
filesystem are test infrastructure, not a production cloud adapter.
