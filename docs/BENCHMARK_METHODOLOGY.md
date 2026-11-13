# Benchmark methodology

`benchmarks/audit_experiment.cpp` compares B1 uniform sampling, B2 uniform
sampling with repair, B3 diagnostic risk sampling, and full Q-SAFE. The runner
uses the same size, seed, fault pattern, corruption fraction, sample fraction,
and round count across strategies. Each run emits per-round CSV and a separate
JSON manifest with source revision, dirty-file count, build and host details,
dependency versions, seed, parameters, and risk-config digest.

Use `scripts/run_audit_benchmark.sh` for one sampling cost or
`scripts/run_audit_sweep.sh` for a set of sample fractions. The project-local
analysis dependencies are pinned in `requirements-analysis.txt`; run
`analysis/analyze_benchmarks.py` on the resulting CSV files to produce summary
tables, median bootstrap intervals, detection and cost plots, and overhead
tables.

The planned size points are 10, 100, 500, and 1,000 MB where practical. The
recorded 10 MB study used 30 repetitions and 10 rounds at three sample costs
for localized and random corruption. The 100 MB study used 30 repetitions and
10 rounds at 5% sampling for both patterns. At 500 MB, 30 repetitions of one
round completed for all strategies at 5% sampling; a separate three-round
follow-up stalled during Q-SAFE. A one-round 1 GB smoke check completed for all
strategies, while its 30-repetition follow-up stopped after six complete
Q-SAFE rows. See [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md) for results and
exclusions.

Runs are synthetic, local, and hardware-specific. Censored detection times are
reported as round 11 for a 10-round trial. Bootstrap intervals are exploratory
and do not establish general superiority. B3 retains a uniform baseline sample
to preserve valid challenge semantics, so it is a diagnostic risk-only
comparison rather than a drop-in full-system strategy.
