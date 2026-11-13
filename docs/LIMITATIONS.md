# Limitations and future work

- This is a local simulator, not a production cloud client or distributed
  service. It does not address network behavior, production key management, or
  availability guarantees.
- The user-file interface stores plaintext shards and parity on the host disk.
  Linux workspace permissions are restricted to the owner, but data is not
  encrypted at rest. Signing keys are not retained for future versions.
- Sampled Merkle checks do not prove whole-file possession or retrievability.
  A formal PDP/PoR protocol and separate security analysis would be needed.
- ISA-L repair handles supported erasures from authenticated inputs; it does
  not correct Byzantine errors.
- Only supported 4+2 and 6+3 layouts are implemented.
- Risk-weighted sampling has not demonstrated an advantage over uniform
  sampling at matched cost. The tested intervals overlap and must not be
  presented as a superiority result.
- Repeated benchmark results cover 10 MB at three sample costs, 100 MB at one
  cost, and 500 MB at one round/cost. A 1 GB one-round smoke check completed;
  the 30-repetition follow-up did not finish. Benchmark findings are local and
  do not establish a general risk-sampling advantage.
- Ubuntu 26.04.1 on WSL2 is the selected current build environment. Ubuntu
  24.04 was not separately verified.
- The database/checkpoint design detects rollback only when the external
  checkpoint is independently protected.
- Current adversarial tests cover documented API paths; they do not replace
  fuzzing, formal verification, penetration testing, or cryptographic review.
