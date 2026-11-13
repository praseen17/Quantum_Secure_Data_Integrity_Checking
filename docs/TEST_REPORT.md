# Test report

## Recorded verification

The current checkout was freshly configured and built in `build/complete-clean`
in WSL2 Ubuntu 26.04.1, GCC 15.2.0, CMake/Ninja, OpenSSL 3.5.5, liboqs
0.16.0, and ISA-L 2.31.1-3. The clean build directory was `build/complete-clean`.

```sh
cmake -S . -B build/complete-clean -GNinja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$PWD/build/liboqs-install" \
  -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST="$PWD/build/current/_deps/googletest-src"
cmake --build build/complete-clean --parallel 4
ctest --test-dir build/complete-clean --output-on-failure
```

Observed result: **71 tests passed, 0 failed**. This included unit and
integration tests across encoding, hashing, Merkle proofs, manifests,
chunking/storage, audit and risk sampling, fault injection, ISA-L recovery,
commitment-preserving repair, and signed receipts/checkpoints. Added adversarial
coverage included swapped shard payloads, replay under a new challenge,
proofless responses, changed repair roots, invalid receipt signatures, and
checkpoint rollback/tampering cases.

`build/complete-clean/qsafe_demo /tmp/qsafe-demo` completed with 262,144 input
bytes, six verified shards, a signed manifest, signed receipts, and a verified
checkpoint. The user-file CLI and HTTP upload/audit/loss/repair/download flow
also passed a 584,399-byte multi-stripe end-to-end check. A one-repetition,
one-round, 1 MB random-pattern benchmark smoke cell completed for all four
strategies; benchmark analysis labelled it preliminary. Tests provide evidence
for covered paths, not a security proof. The complete case mapping is in
[ADVERSARIAL_RESULTS.md](ADVERSARIAL_RESULTS.md).
