# Security assumptions

- Trusted owner and auditor public keys are provisioned independently of the
  cloud. Private keys are generated for the demo in memory and are not
  persisted or suitable for production use.
- OpenSSL's cryptographic random number generator is correctly seeded and
  operating-system entropy is available.
- SHA-256 collision resistance and ML-DSA implementation security are assumed;
  the tested liboqs build enables ML-DSA-44 and ML-DSA-65.
- The verifier's external receipt checkpoint is stored and advanced in a
  rollback-resistant manner. The application detects disagreement but cannot
  protect a checkpoint stored in the same attacker-controlled domain as the
  log.
- Host, compiler, dependency supply chain, filesystem, and SQLite behavior are
  trusted. The project does not harden those components.
- The simulated store's immutable-version behavior is an application rule, not
  a guarantee from a remote storage service.

Using ML-DSA does not make the whole system quantum-secure: SHA-256, protocol
composition, implementation, key custody, and operational controls retain
their own assumptions. No formal proof of a PDP/PoR scheme or end-to-end quantum
security is claimed.
