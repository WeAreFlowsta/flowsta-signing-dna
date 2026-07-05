# Flowsta Signing DNA

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-production-brightgreen.svg)](https://flowsta.com)
[![Holochain](https://img.shields.io/badge/holochain-0.6.0-6c5ce7.svg)](https://www.holochain.org/)

Holochain DNA behind [Sign It](https://flowsta.com/sign-it/) — Flowsta's cryptographic file signing and verification service. Part of the [Flowsta](https://flowsta.com) ecosystem.

## What It Does

- Stores Ed25519 **signatures over SHA-256 file hashes** on a public DHT
- Anyone can **verify a signature** without contacting a central authority
- **Metadata** per signature: signing intent, AI generation disclosure, content rights manifest, file integrity report
- **Revocation**: signers can revoke their own signatures — the revocation is itself a signed entry, visible alongside the original
- **Perceptual hashing**: optional fuzzy-match hash bands so modified copies of images, audio, and video can find their origin signature
- **Multi-signer**: multiple agents can co-sign the same file hash
- **Thumbnails**: signers can attach a small visual preview (≤ 15 KB) to their signature

## Why a Separate DNA?

Flowsta splits its Holochain network into three DNAs with different trust and privacy properties:

- **[Identity DNA](https://github.com/WeAreFlowsta/flowsta-identity-dna)** (public) — public profile, agent links, W3C DID
- **[Private DNA](https://github.com/WeAreFlowsta/flowsta-private-dna)** (encrypted) — email, recovery phrase, sessions
- **Signing DNA** (public) — this repo — cryptographic signatures over files

Signatures are designed to be public and permanent. Keeping them on their own DNA means verification stays trustless and the signing network can scale independently.

## Entry Types

| Entry | Purpose |
|-------|---------|
| `SignatureRecord` | Ed25519 signature over a SHA-256 file hash, with optional metadata |
| `RevocationEntry` | Marks a previous signature as revoked (signed by the same agent) |
| `ContentRightsManifest` | Machine-readable license + AI training policy attached to a signature |
| `IntegrityReport` | File-level integrity info the signer commits to at sign time |
| `PerceptualHashBands` | LSH bands for fuzzy matching of images/audio/video |
| `Thumbnail` | Signer-attached visual preview (data URI, ≤ 15 KB) |

## Building

```bash
cd v1.4
bash build.sh
```

Requirements:
- Rust with the `wasm32-unknown-unknown` target
- Holochain CLI (`hc`) version 0.6.0

Output: `workdir/flowsta_signing_v1_4_happ.happ`

## Versions

| Version | Status | Changes |
|---------|--------|---------|
| v1.4 | ✅ Current | Cross-conductor thumbnails + webhook support |
| v1.3 | ⚠️ Deprecated | Thumbnails + metadata extensions |
| v1.2 | ⚠️ Deprecated | Web dashboard signing + cross-agent queries |
| v1.1 | ❌ EOL | Perceptual hashing support added |
| v1.0 | ❌ EOL | Initial release: SignatureRecord, RevocationEntry, ContentRights, IntegrityReport |

### Coordinator revisions (v1.4)

Coordinator-only changes don't alter the DNA hash, so they roll out to live
cells via Holochain's `UpdateCoordinators` admin call — no reinstall, no
data migration, no network split. Integrity zomes are untouched.

| Rev | Changes |
|-----|---------|
| 3 | Adds `get_own_revocations_for_signature` — a local-read variant for the signer's own view (a revocation can only be authored by its signer, so the local database is complete). |
| 2 | Self-authored lookups (`get_my_signatures`, `get_my_signatures_since`, `set_thumbnail`'s existing-link check, `get_thumbnail`) read with `GetStrategy::Local` — these only ever touch data the calling agent authored, and a network lookup there could hang for minutes on a freshly started conductor. Cross-agent surfaces (hash, agent, perceptual-band, and revocation lookups for verification) keep the network strategy. |
| 1 | As released with v1.4. |

Rule of thumb encoded here: **reads of self-authored data are local; reads
that verify other agents' claims go to the network.**

See [SECURITY.md](SECURITY.md) for the currently supported versions.

## Documentation

- **Sign It overview**: https://flowsta.com/sign-it/
- **Developer docs**: https://docs.flowsta.com/sign-it/
- **SDK reference**: https://docs.flowsta.com/sign-it/sdk-reference
- **Verification API**: https://docs.flowsta.com/sign-it/verification-api

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Please report security vulnerabilities to **security@flowsta.com** rather than opening a public issue. See [SECURITY.md](SECURITY.md) for the full disclosure policy and what's safe to store on this DNA.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
