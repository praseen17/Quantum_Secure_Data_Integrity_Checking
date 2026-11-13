# Q-SAFE build guide

## Supported build environment

The verified environment is WSL2 with Ubuntu 26.04.1, GCC 15.2, CMake 4.2,
Ninja 1.13, OpenSSL 3.5, SQLite 3.46, ISA-L 2.31, liboqs 0.16, and GoogleTest
1.17. Other recent Ubuntu versions may work, but have not been verified in
this project workspace.

## First-time setup

From the repository root:

```sh
scripts/setup_ubuntu.sh
```

The script installs Ubuntu build dependencies with `apt`, builds liboqs 0.16.0
with the project helper, and installs the pinned Python analysis dependencies
into `analysis/.venv`. It uses `sudo` for system packages and requires network
access to fetch source dependencies.

## Configure and compile

```sh
scripts/build.sh
```

The default build directory is `build/current`. To choose a different build
directory or job count:

```sh
QSAFE_BUILD_DIR="$PWD/build/local" QSAFE_JOBS=4 scripts/build.sh
```

The build creates the core libraries, `qsafe_demo`, the benchmark executable,
and `qsafe_vault`. Build artifacts are local and are excluded from the source
repository.

## Run the verification suite and examples

```sh
scripts/test.sh
scripts/run_demo.sh /tmp/qsafe-demo
scripts/run_interface.sh
```

The test script builds the configured tree and runs CTest. The demo and browser
interface write simulator data only to the output or data directory you
choose. The default browser data directory is
`~/.local/share/qsafe-ui/`.

## Troubleshooting

- **`liboqs` cannot be found:** run `scripts/setup_ubuntu.sh` and then
  `scripts/build.sh`; the setup helper installs liboqs under `build/`.
- **ISA-L headers or library are missing:** install `libisal-dev` with apt and
  rerun `scripts/build.sh`.
- **GoogleTest fetch fails:** ensure network access is available during the
  first CMake configure, or provide a local GoogleTest source tree through
  CMake's `FETCHCONTENT_SOURCE_DIR_GOOGLETEST` option.
- **Port 8765 is occupied:** start with `scripts/run_interface.sh --port 8787`
  and open `http://127.0.0.1:8787`.
- **Vault executable missing:** run `scripts/build.sh`, or set
  `QSAFE_BUILD_DIR` consistently for both build and interface launch.

For module scope and security limitations, see [THREAT_MODEL.md](THREAT_MODEL.md)
and [LIMITATIONS.md](LIMITATIONS.md).
