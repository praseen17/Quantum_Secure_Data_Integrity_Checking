# Dependencies

The project uses C++17, CMake, and Ninja on its validated WSL2 Linux
environment (Ubuntu 26.04.1). Ubuntu 24.04 is the intended deployment target in
the original prompt but has not been tested in this workspace.

| Dependency | Recorded version/source | Purpose |
|---|---|---|
| GCC | 15.2.0 | C++17 compiler |
| CMake | 4.2.3 | Configure and build |
| Ninja | 1.13.2 | Build generator |
| OpenSSL | 3.5.5 | EVP SHA-256 and cryptographic randomness |
| SQLite | 3.46.1 | Shard metadata and receipt log persistence |
| ISA-L | 2.31.1-3 | Reed–Solomon encoding and recovery |
| liboqs | 0.16.0, upstream tag | ML-DSA signatures; built with `scripts/build_liboqs.sh` |
| GoogleTest | 1.17.0, CMake FetchContent | Unit and integration tests |
| Python | 3.14.4 in analysis environment | Benchmark analysis |
| pandas, NumPy, SciPy, matplotlib | pinned in `requirements-analysis.txt` | Tables, intervals, statistical analysis, plots |

Ubuntu packages for the native dependencies are listed in
`DEPENDENCIES.md` at the repository root. The setup helper installs those
packages and builds liboqs. GoogleTest is fetched at configure time unless
already cached. Dependency versions in benchmark manifests describe the
recorded local environment; they are not a compatibility promise for all
platforms.
