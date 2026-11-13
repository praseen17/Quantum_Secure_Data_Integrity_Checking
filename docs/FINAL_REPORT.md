# Q-SAFE delivery report

**Status: Implementation complete; benchmark coverage is partial.** The user
file CLI, browser interface, recovery flow, tests, and operating/deployment
guide are complete for the selected Ubuntu 26.04.1 WSL environment. Earlier
“partially complete” wording incorrectly treated optional large-scale research
benchmark coverage as an unfinished product implementation item.

## Implementation

Implemented components cover project/dependency setup; canonical encoding and
SHA-256; Merkle trees; ML-DSA-signed manifests; chunking and SQLite simulated
storage; audit and hypergeometric estimates; deterministic fault injection;
ISA-L Reed–Solomon coding; commitment-preserving repair; risk sampling; signed
receipts and externally checked hash-chain checkpoints; benchmark harness and
analysis; adversarial coverage; project documentation and helper scripts.

## Environment and dependencies

Verified environment: WSL2 Ubuntu 26.04.1, GCC 15.2.0, CMake 4.2.3, Ninja
1.13.2, OpenSSL 3.5.5, SQLite 3.46.1, ISA-L 2.31.1-3, liboqs 0.16.0, and
GoogleTest 1.17.0. Analysis uses Python 3.14.4 and the pinned packages in
`requirements-analysis.txt`. Ubuntu 24.04 was not available for validation.

## Build and tests

Current-checkout commands:

```sh
scripts/build.sh
scripts/test.sh
scripts/run_demo.sh /tmp/qsafe-demo
```

The fresh `build/complete-clean` configure and build succeeded. CTest reported
**71 passed, 0 failed**. Three new vault workflow tests cover multi-stripe
ingest/audit/loss/recovery, malformed metadata rejection, and workspace
signature tampering. The original `qsafe_demo` reported 262,144 input bytes,
six verified shards, a signed manifest, signed receipts, and a verified
checkpoint.

## Benchmark evidence

The current-checkout 1 MB random-pattern smoke cell completed with one
repetition, one round, and 5% sampling for all four strategies; analysis ran
and labelled the result preliminary because it is below the 30-repetition
target. The broader recorded experiments are summarized in
`BENCHMARK_REPORT.md`: repeated 10 MB cells and a 100 MB repeated cell show
overlapping uniform/Q-SAFE detection-time intervals. A 500 MB, 30-repetition
one-round cell and a 1 GiB one-run scale check completed. Their separate
multi-round/30-repetition follow-ups stalled during full Q-SAFE and are
excluded as incomplete.

## Security scope and remaining work

The user-file CLI and local web interface now support ingest, integrity
auditing, explicit missing-shard simulation, repair of selected missing or
corrupt shards, and byte-verified restoration. A manual HTTP end-to-end check
uploaded a 584,399-byte file, verified 18 shards, detected an unavailable
shard, repaired it, and downloaded an exact byte-for-byte match. See
`USER_AND_DEPLOYMENT_GUIDE.md` for normal operation and safety limits.

The project does not prove whole-file possession or retrievability and does
not claim formal PDP/PoR security or end-to-end quantum security. See
`THREAT_MODEL.md`, `SECURITY_ASSUMPTIONS.md`, and `LIMITATIONS.md`. A local
browser interface is available via `scripts/run_interface.sh`; it can ingest,
audit, repair, and restore a user's own file in the local simulator. It is not a
production cloud service.

There is no remaining implementation item for the local user-file prototype.
The limits of the benchmark evidence and product security scope are documented
in `BENCHMARK_REPORT.md`, `LIMITATIONS.md`, and `THREAT_MODEL.md`.
