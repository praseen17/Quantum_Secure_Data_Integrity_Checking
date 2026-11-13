# Q-SAFE user guide

This guide explains how to check a file, understand integrity results, and
recover a missing or damaged shard using the local browser interface or CLI.

## Start the browser interface

From the Q-SAFE project directory in WSL:

```sh
scripts/run_interface.sh
```

Open <http://127.0.0.1:8765>. Keep the terminal open while using the interface.
The server is bound to loopback and is not a public website.

## Browser workflow

1. Choose **Add a file** or drop a file into the upload panel. The browser
   accepts files up to 128 MiB. Q-SAFE divides the uploaded bytes into chunks,
   creates Reed–Solomon parity, and signs a Merkle commitment to that uploaded
   version.
2. Select the stored file and choose an audit size. Use a small sample for a
   quick check or set the count to all shards for a full scan. A sampled audit
   checks only the selected shards and can miss damage elsewhere.
3. Choose **Simulate missing shard** to mark the selected index unavailable in
   the local simulator. The interface now runs a full audit automatically and
   shows the flagged index and missing-shard count. This action changes the
   simulated stored copy; it does not alter the manifest root.
4. Choose **Recover file** for the flagged index. Q-SAFE reconstructs the shard
   from authenticated same-stripe inputs, checks it against the original
   signed commitment, and verifies the original data shards before preparing
   the restored file.
5. Choose **Download recovered file** and compare it with your independent
   original. Keep an independent backup; the simulator is not a backup service.

The 4+2 layout can recover up to two unavailable shards in a stripe when the
remaining required inputs are present and authenticate. It fails closed when
there are too many erasures or the reconstruction does not match the original
commitment.

## Understanding tampering

Q-SAFE treats the bytes present at **ingest time** as the reference version.
If a file was already altered before you upload it, Q-SAFE signs that altered
version as the new baseline; it cannot know what the file contained before
ingest. To test detection, first upload a known-good file, then alter or remove
one of its stored shards in the simulator workspace and run a full audit. The
browser's **Simulate missing shard** button is a safe way to exercise the loss
and recovery path without modifying the signed manifest.

The signed manifest and owner public key are local workspace metadata. This
prototype does not encrypt data at rest, retain the signing private key for
later ingests, or connect to a remote cloud provider. Do not upload sensitive
files to a host you do not control.

## CLI workflow

The CLI supports files up to 256 MiB. Use a fresh workspace directory for each
file version:

```sh
build/current/qsafe_vault ingest ./example.bin "$HOME/qsafe-data/example"
build/current/qsafe_vault inspect "$HOME/qsafe-data/example"
build/current/qsafe_vault audit "$HOME/qsafe-data/example" 999999
build/current/qsafe_vault lose "$HOME/qsafe-data/example" 0
build/current/qsafe_vault audit "$HOME/qsafe-data/example" 999999
build/current/qsafe_vault recover "$HOME/qsafe-data/example" 0 ./recovered.bin
```

Replace `999999` with the total shard count shown by `inspect`. The audit JSON
includes flagged shard indexes. `restore WORKSPACE OUTPUT_FILE` verifies and
restores an intact workspace without first simulating a loss.

See [BUILD_GUIDE.md](BUILD_GUIDE.md) to install and compile the project and
[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for persistent local service setup.
