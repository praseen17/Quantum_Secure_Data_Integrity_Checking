# Security and research claim traceability

This prototype report maps claims to evidence. A passing test is evidence for
the tested input path only; it is not a security proof.

| Claim | Evidence category | Evidence or assumption | Limits |
|---|---|---|---|
| Canonical fields have a single bounded encoding and malformed UTF-8/trailing bytes are rejected. | Test | `CanonicalEncoding.*` | Does not prove all future formats use the codec. |
| Sampled shard bytes are bound to file, version, index, and the signed Merkle root. | Test | `MerkleIntegration.*`, `AuditIntegration.*`, `Manifest.ChangingAnySignedFieldInvalidatesSignature` | Only sampled shards are checked. |
| Challenges bind nonce, version, and ordered sample indices. | Test | `AuditIntegration.RejectsOldNonceStaleVersionAndReorderedIndices` | CSPRNG quality is assumed from OpenSSL `RAND_bytes`; the prototype does not formally analyze it. |
| Uniform audit detection probability follows the finite-population hypergeometric model. | Analysis plus tests | `detectionProbability`, `AuditSampling.DetectionProbabilityMatchesHypergeometricFixtures` | Applies to uniform sampling under the model assumptions; observed benchmark validation remains pending. |
| Risk sampling preserves baseline indices and favors higher-scored stripes. | Test | `RiskSampling.PreservesBaselineWithoutDuplicatesAndZeroCrIsUnchanged`, `RiskSampling.HigherRiskStripesAreSelectedMoreOften` | No claim that it improves all fault patterns or at matched audit cost. |
| Signed receipt edits, log gaps, and rollback against the current external checkpoint are detected. | Test | `Receipt.CanonicalRoundTripAndSignatureBindAllFields`, `AuditLog.*`, `Gate4.*` | Checkpoint freshness and protection from rollback are an operational trust assumption: it must be stored independently and advanced reliably. |
| Reed-Solomon 4+2/6+3 can recover supported erasures. | Test | `ReedSolomonCodec.*` | Depends on ISA-L behavior and a valid codeword; no Byzantine error correction claim. |
| Repair preserves the original commitment and rejects unauthenticated inputs. | Test | `CommitmentRepair.*` | Repair is limited to configured supported layouts and local simulated storage. |
| A user can ingest a file, persist its signed workspace, audit it, repair a flagged or unavailable shard, and restore the original bytes. | Test and end-to-end run | `VaultWorkspace.IngestsAuditsRepairsAndRestoresMultipleStripes`, `VaultWorkspace.RejectsTamperedSignedWorkspaceMetadata`, HTTP upload/audit/loss/recovery/download flow | Local simulator only; input limits are 128 MiB through the UI and 256 MiB through the CLI. Data is plaintext at rest. |
| The browser workflow is restricted to the local machine and handles owner data with restrictive file permissions. | Implementation check | `interface/server.py` loopback bind, origin check, upload bound, owner-only data directory; CLI workspace permission setup | No authentication, TLS, encryption at rest, or production hardening. Do not expose directly to a network. |
| ML-DSA-44/65 key generation, signing, and verification work in the selected liboqs build. | Test | `qsafe_liboqs_gate`, manifest and receipt signature tests | Does not establish end-to-end quantum security; SHA-256, SQLite, host, keys, and protocol composition have separate assumptions. |
| Q-SAFE proves the cloud possesses the complete file. | Unsupported | None | A cloud that fetches sampled shards on demand from elsewhere can pass. A PDP/PoR protocol and separate analysis are required. |
| Risk-weighted auditing outperforms uniform auditing. | Not demonstrated | Repeated 10 MiB and 100 MiB measured intervals overlap in the documented cells. | No superiority claim is supported by current measurements. |

## Current test gaps

The API has no cloud-supplied leaf-hash-list input, no caller-provided success
flag, and no operation that permits repair under a new root; those exact attack
forms are therefore not separately exercised as black-box tests. The checkpoint
file is treated as externally protected; the implementation cannot prevent an
attacker who can replace both the database and the trusted checkpoint from
rewinding both. See `ADVERSARIAL_RESULTS.md` for the case-by-case status.
