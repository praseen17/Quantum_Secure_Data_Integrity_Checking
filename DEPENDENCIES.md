# Dependencies

| Dependency | Version | Role | Source |
|---|---:|---|---|
| C++ compiler | GCC 15.2.0 | Build-time | Ubuntu 26.04 |
| CMake | 4.2.3 | Build-time | Ubuntu 26.04 |
| OpenSSL | 3.5.5 | Runtime/build-time | System package |
| SQLite | 3.46.1 | Runtime/build-time | System package |
| ISA-L | 2.31.1 | Runtime/build-time, Reed-Solomon coding | System package |
| liboqs | 0.16.0 | Runtime/build-time, ML-DSA | Upstream release, built by `scripts/build_liboqs.sh` |
| GoogleTest | 1.17.0 | Test-time | CMake FetchContent |
| Python | 3.14.0 | Benchmark analysis only | WSL system Python |
| NumPy | 2.5.4 | Benchmark analysis only | `requirements-analysis.txt` |
| pandas | 3.1.1 | Benchmark analysis only | `requirements-analysis.txt` |
| matplotlib | 3.11.2 | Benchmark plots only | `requirements-analysis.txt` |
| SciPy | 1.18.1 | Hypergeometric reference curves | `requirements-analysis.txt` |
