# Q-SAFE prototype

Q-SAFE is a C++17 research prototype for sampled integrity checks of data stored
in a simulated cloud. It combines canonical encoding, SHA-256 Merkle proofs,
ML-DSA-signed manifests and receipts, uniform and risk-weighted challenges,
SQLite-backed shard storage and receipt history, and ISA-L Reed-Solomon repair.

## Setup and build on the current WSL environment

The project was built on WSL2 Ubuntu 26.04.1. Install system and analysis
dependencies using `scripts/setup_ubuntu.sh`; it also builds liboqs 0.16.0
from its upstream tag. CMake fetches GoogleTest 1.17.0.

```sh
scripts/build.sh
scripts/test.sh
```

Run the end-to-end demonstration with an optional output directory:

```sh
scripts/run_demo.sh /tmp/qsafe-demo
```

The demo uses ephemeral keys and writes simulated shards, a SQLite receipt log,
and an external checkpoint to the chosen directory. It is for local evaluation,
not production key management.

## Browser interface

Start the local-only web interface after building:

```sh
scripts/run_interface.sh
```

Open <http://127.0.0.1:8765> to add your own file (up to 128 MiB), run a sampled
or full integrity audit, simulate a missing shard, repair it, and download the
restored original. Simulated loss now triggers an immediate full audit and
shows the missing shard index. CLI workflows are available through
`build/current/qsafe_vault`; files are held in the local simulator and are not
sent to a cloud provider.

Separate handbooks are available for the [user workflow](docs/USER_GUIDE.md),
[building](docs/BUILD_GUIDE.md), and
[deployment](docs/DEPLOYMENT_GUIDE.md). The
[preview research report](docs/PREVIEW_RESEARCH_REPORT.md) summarizes current
results and limitations.

Install the pinned analysis dependencies in the project-local environment and
run the benchmark analysis with:

```sh
python3 -m venv analysis/.venv
analysis/.venv/bin/python -m pip install -r requirements-analysis.txt
scripts/run_audit_sweep.sh benchmarks/raw/localized-10mb 10 30 10 localized 20261112
scripts/run_audit_sweep.sh benchmarks/raw/random-10mb 10 30 10 random 20261112
analysis/.venv/bin/python analysis/analyze_benchmarks.py \
  benchmarks/raw/localized-10mb/benchmark.csv \
  benchmarks/raw/random-10mb/benchmark.csv --output benchmarks/analysis
```

The sweep writes one tidy `benchmark.csv` across sample fractions, plus a
manifest for each cell and a sweep manifest. Each runner writes a separate
`run_manifest.json`.
Review [BENCHMARK_REPORT.md](docs/BENCHMARK_REPORT.md) and
[BENCHMARK_METHODOLOGY.md](docs/BENCHMARK_METHODOLOGY.md) for actual trial
counts, results, and exclusions. `scripts/run_benchmarks.sh` accepts an output
directory, file size in MB, repetitions, rounds, pattern, seed, and sample
fractions.

## Project status

Implemented modules and verification evidence are summarized in
[FINAL_REPORT.md](docs/FINAL_REPORT.md). This remains a research prototype, not
a production PDP/PoR service or a proof of end-to-end quantum security.

## Research limitations

This prototype is not a formal proof of data possession or retrievability. A
cloud can fetch sampled shards on demand and pass an audit. The measured
risk-weighted results do not show a clear advantage over uniform sampling.
See [REQUIREMENTS_TRACEABILITY.md](docs/REQUIREMENTS_TRACEABILITY.md)
and [ADVERSARIAL_RESULTS.md](docs/ADVERSARIAL_RESULTS.md) for evidence and gaps.
