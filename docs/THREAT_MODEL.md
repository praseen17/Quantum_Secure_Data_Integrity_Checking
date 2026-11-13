# Threat model

## In scope

The simulated cloud may return missing, altered, stale, reordered, or
wrong-version shard data and proof metadata. It may provide poisoned
Reed–Solomon inputs or malformed audit responses. An attacker may edit, forge,
replay, reorder, delete, or truncate receipts and may replace the receipt
database while the independently stored trusted checkpoint remains intact.
The verifier is expected to reject these cases using signatures, canonical
encodings, challenge binding, Merkle proofs, authenticated repair inputs, the
receipt hash chain, and checkpoint comparison.

## Out of scope

The prototype does not defend against a compromised owner or auditor endpoint,
stolen signing keys, a malicious kernel, side-channel attacks, denial of
service, or an attacker who can roll back both the receipt database and its
trusted checkpoint. The local simulator does not model a real cloud provider,
network, key-management service, or independent auditor deployment.

The user-facing interface runs a single-user local workflow and binds only to
loopback. It has no login or tenant isolation, so a network-hosted deployment
is outside the current security model.

## Security boundary

Sampled Merkle verification establishes that returned sampled shard bytes are
consistent with a signed root, for the verified challenge. It does not prove
the cloud possesses the entire file or can retrieve arbitrary data later. The
prototype is not a PDP or PoR construction. Reed–Solomon repair addresses
erasures with authenticated inputs; it does not provide Byzantine error
correction. The trust assumptions and cryptographic scope are detailed in
[SECURITY_ASSUMPTIONS.md](SECURITY_ASSUMPTIONS.md).
