# Adversarial case results

Expected outcome is fail closed for an invalid proof, response, signature,
repair input, or stale trusted state. Actual results below are based on the
clean current-checkout suite (71 tests, 0 failures).

| Adversarial case | Expected | Actual evidence/status |
|---|---|---|
| Modified shard | Reject as corrupt | Pass: `AuditIntegration.DetectsModifiedAndUnavailableShards` |
| Swapped shard payloads | Reject | Pass: `AdversarialAudit.RejectsSwappedPayloadsReplayAgainstNewChallengeAndProoflessSuccess` |
| Wrong Merkle path orientation | Reject | Pass: `MerkleTree.RejectsReorderedTruncatedAndExtendedProofs`, all-index proof verification |
| Valid path presented for another index | Reject | Pass: `MerkleTree.RejectsWrongIndexAndForeignLeaf` |
| Stale manifest replay | Reject stale checkpoint | Pass: `CommitmentRepair.ReportsUnrecoverableStripeAndRejectsStaleManifest`; audit stale checkpoint test |
| Manifest version changed without a valid signature | Reject | Pass: `Manifest.ChangingAnySignedFieldInvalidatesSignature` |
| Attacker replaces manifest and key together | Reject under caller-pinned trusted key | Wrong trusted key rejected by `Manifest.RejectsWrongTrustedKeyAndTruncatedSignature`; pinning is an explicit caller assumption |
| Forged receipt | Reject | Pass: `AuditLog.RejectsEditedEntryAndForgedReceipt` |
| Log rollback to an older prefix | Reject against current external checkpoint | Pass: `AuditLog.DetectsOlderValidLogAgainstCurrentCheckpoint` |
| Missing/corrupted checkpoint | Reject | Pass: `AuditLog.RejectsMissingAndCorruptedExternalCheckpoint` |
| Repair with a substituted shard | Reject | Pass: `CommitmentRepair.RejectsPoisonedDataOrParityBeforeDecoding` |
| Tampered local recovery metadata | Reject | Pass: `VaultWorkspace.RejectsTamperedSignedWorkspaceMetadata` |
| Malformed local recovery metadata | Reject | Pass: `VaultWorkspace.RejectsMalformedWorkspaceMetadata` |
| Correct shard at wrong global index | Reject | Pass: `MerkleTree.RejectsWrongIndexAndForeignLeaf` and repair proof-index cases |
| Repair requested under a new root | Reject | Pass: `AdversarialRepair.RejectsRepairAgainstAChangedSignedRoot` |
| Response with old nonce | Reject | Pass: `AuditIntegration.RejectsOldNonceStaleVersionAndReorderedIndices` |
| Response replayed against a new challenge | Reject | Pass: `AdversarialAudit.RejectsSwappedPayloadsReplayAgainstNewChallengeAndProoflessSuccess` |
| Response indices reordered | Reject | Pass: `AuditIntegration.RejectsOldNonceStaleVersionAndReorderedIndices` |
| Success flag without a valid path | Reject | Pass with proofless response: `AdversarialAudit.RejectsSwappedPayloadsReplayAgainstNewChallengeAndProoflessSuccess`; the API has no caller-provided success flag |
| Forged cloud-supplied leaf-hash list | Reject | No cloud leaf-list input exists; leaves are computed from returned bytes |
| Cloud withholds proof metadata during repair | Fail repair | Pass: `CommitmentRepair.FailsClosedWhenProofMetadataIsMissingTruncatedOrForWrongIndex` |

No listed passing test establishes formal security. The externally stored
checkpoint must be protected and advanced independently of the SQLite log.
