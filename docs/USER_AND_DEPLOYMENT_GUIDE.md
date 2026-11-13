# Q-SAFE user and deployment guide

## What users can do

Q-SAFE now supports users' own files in its local simulated cloud. The browser
interface can ingest a file, run a sampled integrity audit, simulate a missing
shard, repair it, and download the reconstructed original. The CLI exposes the
same core operations. The interface has no file-size upload above 128 MiB; the
CLI vault accepts files up to 256 MiB. These limits keep the research
prototype's in-memory chunking and Merkle processing bounded.

This is local storage and simulation. It does not connect to AWS, Azure,
Google Cloud, or any remote provider. Files are stored as plaintext shards,
parity, proof metadata, and a SQLite index in the local workspace. The service
sets owner-only directory/file permissions on Linux; it does not encrypt data
at rest. Keep an independent backup of original files.

## Install and start

On the validated WSL2 Ubuntu environment, from the project root:

```sh
scripts/setup_ubuntu.sh
scripts/build.sh
scripts/test.sh
scripts/run_interface.sh
```

Open <http://127.0.0.1:8765>. The server binds to loopback only. Keep its
terminal open; press **Ctrl+C** to stop it. To choose another port:

```sh
scripts/run_interface.sh --port 8787
```

The default persistent data directory is `~/.local/share/qsafe-ui/`. To choose
another directory:

```sh
scripts/run_interface.sh --data-dir /path/to/qsafe-data
```

Workspace data remains on disk after the interface stops. Protect and back up
that directory appropriately. To clear a test workspace, stop the server and
remove the corresponding session directory under the data directory.

## Browser workflow

1. **Add a file.** Choose a file or drop it in the upload area. Q-SAFE splits it
   into 64 KiB chunks, pads the last data stripe, and forms 4+2 Reed–Solomon
   stripes. A signed SHA-256 Merkle manifest binds the file identity, version,
   shard indices, and contents. The original upload is removed after ingest;
   the workspace stores data shards, parity shards, proofs, and public
   verification metadata.
2. **Run an integrity audit.** Enter how many shards to sample. By default the
   interface selects about 5% (at least one). Set the count to the total shard
   count for a full scan. Each sampled shard and proof is checked against the
   owner-signed root. A sample audit can miss damage in unsampled shards; it is
   not a proof of possession or future retrievability.
3. **Identify a problem.** Audits list the exact sampled shard indexes that
   were corrupt, unavailable, or inconclusive. The first flagged index is
   selected automatically; you can enter another index if you know which
   shard needs repair. To practice without a real fault, enter any shard index
   and select **Simulate missing shard**. That marks it unavailable only in
   the simulator and does not alter the signed root or stored shard bytes. The
   interface then runs a full audit and displays the missing shard result.
4. **Recover the file.** Select **Recover file** for the chosen index. Q-SAFE
   authenticates the other shards in that 4+2 stripe, reconstructs the target,
   checks it against the original signed Merkle root, stores it, and re-audits
   it. It then verifies every original data shard and prepares the restored
   file for download.
5. **Download.** Select **Download recovered file**. The browser saves the
   reconstructed bytes as `recovered-file.bin`; rename it to the original name
   if needed.

Each 4+2 stripe can recover up to two unavailable shards, provided enough
authenticated shards remain. Corrupt or unavailable decode inputs are rejected.
If a stripe has too many missing shards, restore fails closed. A user may
recover one target shard per operation and rerun recovery for another loss.

## Command-line workflow

The `qsafe_vault` executable accepts a file and a workspace directory. Example:

```sh
build/current/qsafe_vault ingest ./important.bin "$HOME/qsafe-data/session-1"
build/current/qsafe_vault inspect "$HOME/qsafe-data/session-1"
build/current/qsafe_vault lose "$HOME/qsafe-data/session-1" 3
build/current/qsafe_vault audit "$HOME/qsafe-data/session-1" 12
build/current/qsafe_vault recover "$HOME/qsafe-data/session-1" 3 ./recovered.bin
```

Each command emits one JSON object. `recover` repairs the requested shard and
writes the reconstructed original file only after verifying all original data
shards. To restore an intact workspace without repairing a shard first, use:

```sh
build/current/qsafe_vault restore "$HOME/qsafe-data/session-1" ./restored.bin
```

The CLI can ingest up to 256 MiB. A workspace holds one immutable file version;
ingest a new file into a new workspace directory.

## How the design works

The owner generates an ML-DSA-44 signing key during ingest, signs the manifest,
and discards the private key when that process ends. The public key and
signature are retained for later verification. The cloud simulator stores
shards and Merkle proofs. An audit creates a fresh nonce-bound challenge and
verifies the returned sample. Repair uses authenticated same-stripe inputs,
the ISA-L codec, the saved original target proof, and a targeted post-repair
check. No new manifest root is created during repair.

This current vault interface does not persist the owner's private key and does
not create signed audit receipts for each vault audit. Those capabilities are
present in the lower-level Q-SAFE demo/receipt modules; adding durable key
management and a production audit-log lifecycle requires a separate secure
key-custody design. See [THREAT_MODEL.md](THREAT_MODEL.md) and
[SECURITY_ASSUMPTIONS.md](SECURITY_ASSUMPTIONS.md).

## Deployment

The supported use is a private demo on one Ubuntu Linux host. Install the
dependencies, build, run the tests, and start the loopback-only server as above.
For a remote private demo machine, keep the service on loopback and use an SSH
tunnel from the browser workstation:

```sh
ssh -L 8765:127.0.0.1:8765 username@demo-host
```

Then open <http://127.0.0.1:8765> on the workstation. Do not bind this server
to `0.0.0.0` or put it directly on the public internet. It has no user
accounts, TLS termination, encryption at rest, managed key storage, remote
cloud adapter, tenant isolation, or production hardening. A production service
would need these controls, an authenticated frontend/reverse proxy, durable
trusted checkpoints, monitoring, deployment-specific limits, and independent
security review.

The validated build environment is WSL2 Ubuntu 26.04.1. Ubuntu 24.04 remains
the intended target in the supplied specification but was not available for
verification in this workspace.
