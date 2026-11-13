# Q-SAFE benchmark report

## Experiment configuration

- Source revisions are recorded in each run manifest. The user-file workflow is the current implementation revision; benchmark manifests retain the earlier revisions used for those experiments.
- Build: Release, GCC 15.2.0, WSL2 Ubuntu 26.04.1; CPU Intel Core i5-12500H
- Dependencies: liboqs 0.16.0 (`ML-DSA-44`), ISA-L 2.31.1-3, OpenSSL 3.5.5
- Codec: 4+2; file size: 10 MiB; 30 repetitions per cell; 10 rounds per repetition
- Fault patterns: one recurring localized damaged shard; fixed random corruption at 2%
- Sample fractions: 1%, 5%, 10%; the same size, fault seed and parameters are used across four strategies
- Audit costs are closely matched: mean bytes transferred per audit differ by less than 0.01% between B1 uniform and full Q-SAFE within each cost/pattern cell.

The raw per-round CSVs and run manifests are in the ignored local directory
`benchmarks/raw/`. The analysis outputs include the empirical/theoretical
detection plot, time-to-detection intervals, repair traffic plot, signature
time share, and storage/metadata table.

## Uniform versus full Q-SAFE

Time-to-detection is the first round with a detected fault. Runs with no
detection during ten rounds are right-censored and assigned round 11 for the
median/interval calculation. Intervals are bootstrap 95% intervals for the
median.

| Pattern | Sample fraction | Uniform median rounds (95% CI) | Q-SAFE median rounds (95% CI) |
|---|---:|---:|---:|
| Localized | 1% | 11 [11, 11] | 11 [11, 11] |
| Localized | 5% | 11 [9, 11] | 11 [10, 11] |
| Localized | 10% | 7.5 [5, 11] | 8 [5.5, 10.5] |
| Random | 1% | 11 [9, 11] | 11 [10, 11] |
| Random | 5% | 4 [2, 6] | 3 [2, 6.5] |
| Random | 10% | 3 [2, 4] | 2 [1, 3] |

The intervals overlap in all six cells. These measurements do not show a clear
detection-time difference between uniform and full Q-SAFE at the tested size,
sampling fractions, patterns, and round limit. They do not support a general
claim that risk-weighted sampling is superior.

## 100 MiB repeated cell

At 100 MiB, the 5% sampling cell was repeated 30 times for ten rounds under
both patterns. Uniform versus full Q-SAFE medians and bootstrap 95% intervals:

| Pattern | Uniform median rounds (95% CI) | Q-SAFE median rounds (95% CI) |
|---|---:|---:|
| Localized | 11 [6, 11] | 10 [5.5, 11] |
| Random | 1 [1, 1] | 1 [1, 1] |

The intervals overlap in both cases, so these 100 MiB results also show no
clear difference at the tested cost and round limit. Full result CSVs and
manifests are retained in the local raw-data directory.

## Other measured behavior

- The 4+2 shard representation used 1.5× the source bytes (50% parity/storage
  expansion); Merkle proof metadata was about 0.58% of source bytes. This counts
  shard and proof payloads, not filesystem/SQLite allocation overhead.
- Full Q-SAFE wall time includes receipt signing, per-receipt hash-chain append,
  and checkpoint verification. At 10 MiB and 5% sampling, median wall times
  were 21.97 ms (localized) and 21.34 ms (random); baseline audit medians were
  about 1.1 ms. The receipt log and checkpoint work are included in full-system
  time.
- At 500 MiB, a 30-repetition, one-round localized cell completed for all four
  strategies at 5% sampling. Median wall times were 79.37 ms (B1), 79.82 ms
  (B2), 80.24 ms (B3), and 4,717.14 ms (full Q-SAFE). This is a repeated
  per-audit timing result, but one round does not estimate multi-round
  detection time. In a separate 30-repetition, three-round attempt, B1/B2/B3
  finished and Q-SAFE stalled in its first repetition after two rounds; those
  incomplete rows are excluded.
- At 1 GiB, a one-repetition, one-round localized smoke check completed for
  all strategies (about 171–177 ms for B1/B2/B3 and 19.45 s for full Q-SAFE).
  A 30-repetition follow-up completed 30 rows each for B1/B2/B3 and six full
  Q-SAFE rows; the next Q-SAFE repetition stalled and the run was interrupted.
  The partial run is excluded from statistical analysis.

## Limits

Repeated 30-run experiments cover 10 MiB at three cost levels, 100 MiB at one
cost level, and 500 MiB at one round/cost. The 1 GiB measurement is a single-run
scale check; the repeated run did not complete. The 500 MiB one-round cell
supports timing medians but not multi-round detection estimates. Fault schedules are synthetic,
storage is local, and the runner uses a diagnostic B3 mode that retains one
uniform sample before its risk-selected samples so that the challenge remains
valid. Do not generalize these results to remote cloud conditions or a
possession/retrievability guarantee.
