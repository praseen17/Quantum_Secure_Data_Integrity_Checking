# Audit experiment runner

`qsafe_audit_experiment` runs the four requested comparison modes over the same
deterministic input bytes and seeded fault schedule for each repetition:

- `B1_uniform`: uniform sampled proof checks.
- `B2_uniform_repair`: uniform checks followed by commitment-preserving repair.
- `B3_risk_diagnostic`: history-weighted sampling with one uniform seed sample
  retained because the public risk sampler extends a valid baseline challenge.
- `QSAFE_full`: half-size uniform baseline plus risk-weighted samples, repair,
  ML-DSA receipts, and the external-checkpoint log.

Each round writes timing, bytes transferred, detection, repair, signature costs,
storage bytes, and proof metadata bytes. The random pattern uses a fixed seeded
corruption schedule; the localized pattern repeats a single damaged shard over
rounds until repair restores it. The 4+2 layout is used for this runner.

Run one cost cell through `scripts/run_audit_benchmark.sh`, or sweep multiple
sample fractions through `scripts/run_audit_sweep.sh`. The sweep writes only CSV and JSON
deliverables; temporary simulated cloud data is removed after a successful run.
The JSON captures source revision and dirty-file count, build mode, compiler,
OS, CPU, dependency versions, ML-DSA algorithm, risk configuration hash,
parameters, and seed.

The 10 MB, 30-repetition smoke study currently uses one 5% sample-cost cell for
localized and random patterns. It is not a full sweep. Run at least 30
repetitions per sample fraction, and run the specified 10, 100, and 500 MB
sizes before making broad comparisons. B3 is a
diagnostic because it retains one uniform sample to preserve a valid challenge;
account for that sample in the reported audit cost.
