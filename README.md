# Flowsta Signing DNA

Dedicated Holochain DNA for decentralized document signing and verification. Part of the [Sign It](../build-docs/planning/SIGN_IT.md) product.

## What It Does

- Stores cryptographic signatures over file hashes on a public DHT
- Anyone can verify a signature without contacting a central authority
- Supports metadata: signing intent, AI generation disclosure, content rights, file integrity reports
- Supports revocation: signers can revoke their own signatures

## Entry Types

- **SignatureRecord** — Ed25519 signature over a SHA-256 file hash, with optional metadata
- **RevocationEntry** — Marks a previous signature as revoked

## Building

```bash
cd v1.0
bash build.sh
```

Requires:
- Rust with `wasm32-unknown-unknown` target
- Holochain CLI (`hc`) version 0.6.0

## Versions

| Version | Status | Changes |
|---------|--------|---------|
| v1.0 | Current | Initial release: SignatureRecord, RevocationEntry, ContentRights, IntegrityReport |
