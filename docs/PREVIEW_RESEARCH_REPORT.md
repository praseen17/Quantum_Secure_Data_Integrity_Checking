# Q-SAFE preview research report

## Abstract

Q-SAFE is a C++17 research prototype for auditing and repairing files held in a
local simulated cloud. It combines signed manifests, SHA-256 Merkle proofs,
uniform and risk-adaptive challenge sampling, Reed–Solomon parity, authenticated
repair, and a browser/CLI workflow for user files. This report summarizes the
current implementation and the measured evidence; it is a preview, not a
peer-reviewed paper or a formal security proof.

## Research question and design

The benchmark asks whether risk-adaptive audit sampling changes detection time
compared with uniform sampling at matched challenge cost. The data path stores
shards with a signed Merkle commitment. An audit checks challenged shard bytes
and proofs against that commitment. The 4+2 Reed–Solomon layout can reconstruct
up to two erasures per stripe when enough authenticated inputs remain. The
browser interface exposes ingest, audit, simulated loss, repair, and restore
for files up to 128 MiB; the CLI supports up to 256 MiB.

## Experimental setup

Experiments ran on WSL2 Ubuntu 26.04.1 using an Intel Core i5-12500H. The
benchmark compares uniform auditing, uniform auditing with repair, a
risk-sampling diagnostic mode, and full Q-SAFE with receipt/checkpoint work.
Fault schedules are synthetic and storage is local. Repeated 10 MiB trials
used 30 repetitions and 10 rounds at 1%, 5%, and 10% sample costs for localized
and random corruption. Repeated 100 MiB trials used 30 repetitions and 10
rounds at 5% cost for both patterns. Full data tables, run parameters, and
exclusions are in [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md).

## Preliminary findings

- At 10 MiB and 100 MiB, uniform-versus-full-Q-SAFE detection-time bootstrap
  intervals overlap in every reported repeated cell. The available evidence
  does not show a general detection-time advantage for risk sampling.
- At 500 MiB and 5% sampling, 30 one-round repetitions completed. Median audit
  wall times were 79.37 ms for uniform, 79.82 ms for uniform plus repair,
  80.24 ms for the risk diagnostic, and 4.72 s for full Q-SAFE. This one-round
  measurement estimates audit time, not multi-round detection behavior.
- A one-run 1 GiB smoke check completed at 5% sampling: the three comparison
  modes took about 171–177 ms and full Q-SAFE took about 19.45 s. The repeated
  1 GiB follow-up stopped after six complete full-Q-SAFE rows; it is not used
  for statistical inference.
- Full Q-SAFE time includes receipt signing, receipt-chain work, and checkpoint
  verification, so this is a measured cost of the implemented full path.

## Interpretation and limitations

These measurements are preliminary and hardware-specific. They do not support
a claim that risk sampling is superior, or that the prototype provides a
formal proof of data possession or retrievability. A sampled audit can miss
unsampled damage. ML-DSA-signed manifests do not by themselves establish
end-to-end quantum security. The browser vault uses local plaintext storage and
does not connect to a production cloud service. Large multi-round Q-SAFE runs
at 500 MiB and 1 GiB did not finish within the available run window.

Further work should profile receipt and checkpoint costs, complete bounded
multi-round large-file studies, compare against remote storage behavior, define
durable key custody and external checkpoint management, and obtain independent
cryptographic and security review.
