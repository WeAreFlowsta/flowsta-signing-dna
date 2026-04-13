# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please email security@flowsta.com with:

1. **Description** — Detailed explanation of the vulnerability
2. **Steps to Reproduce** — How to trigger the issue
3. **Impact** — Potential consequences (forged signatures, DOS, unauthorized revocation, etc.)
4. **Suggested Fix** — If you have one (optional)
5. **Your Contact Info** — For follow-up questions

### What to Expect

- **Initial Response**: Within 48 hours
- **Status Update**: Within 1 week
- **Fix Timeline**: Depends on severity (critical issues prioritized)
- **Credit**: We'll credit you in our security advisories (unless you prefer anonymity)

## Supported Versions

| Version | Status | Support |
|---------|--------|---------|
| v1.4 | ✅ Current | Actively maintained |
| v1.3 | ⚠️ Deprecated | Security fixes only |
| v1.2 | ⚠️ Deprecated | Security fixes only |
| v1.1 | ❌ End of Life | No support |
| v1.0 | ❌ End of Life | No support |

## Security Model

### Public by Design

The **Flowsta Signing DNA** stores signatures on a **public DHT** by design. A signature isn't useful if it can't be verified by anyone.

- ✅ All signatures are **fully readable by anyone** on the DHT
- ✅ **Every signature is cryptographically bound** to its signer's Ed25519 agent key
- ✅ **Censorship-resistant** — once published, signatures cannot be deleted
- ✅ **Revocation is itself a signed action** — it doesn't delete the original, it publishes a counter-entry

### What's Stored

✅ **By design** (public and permanent):
- SHA-256 file hashes
- Ed25519 signatures by the signer's Holochain agent key
- Intent strings (`Authorship`, `Approval`, `Witness`, `Receipt`, `Agreement`)
- AI generation disclosure (`None`, `Assisted`, `Generated`)
- Content rights manifests (license, AI training policy)
- Perceptual hash bands (for fuzzy lookup of modified images/audio/video)
- Revocation entries (action hash + optional reason)
- Signer-attached thumbnails (≤ 15 KB data URIs)

❌ **Never store on this DNA** (use the Private DNA instead):
- Email addresses or email hashes
- Personal Identifiable Information (PII)
- Authentication credentials
- Recovery phrases
- Display names or personal identifiers

### Critical Property: Signatures Are Forever

Once a signature is committed to the DHT, it is **public and permanent**. This is the point — verifiers need to be able to check it. Design accordingly:

- Users who sign something are committing to a public, immutable record
- Revocation does not delete — it publishes a new entry that anyone checking the signature will see alongside it
- Applications integrating Sign It should make this clear to users before they sign

## Known Security Considerations

### 1. DHT Data is Permanent

Once data is published to the DHT, it **cannot be fully deleted**. Other nodes may retain copies. This is by design for signatures (the whole point is verifiability after the fact), but integrators should be explicit with users about what signing means.

### 2. Only the Signer Can Sign

Signatures are created using the signer's own Holochain agent private key, which lives in Lair keystore on the signer's machine. The signing API requires authentication (JWT session or OAuth with `sign` scope); the public DHT rejects any signature not cryptographically bound to its signer's agent key.

### 3. Only the Signer Can Revoke

Revocation entries must be signed by the same agent key that created the original signature. Others cannot revoke a signature they did not create.

### 4. Thumbnail Integrity

Thumbnails are stored as data URIs attached to a signature by the original signer only. They are not content-verified against the signed file — they are a visual aid chosen by the signer, not a proof.

### 5. Agent Keys

Holochain agent keys (public keys) are visible on the DHT. This is expected and does not compromise security:
- They are designed to be public
- They're used for signing DHT operations
- Private keys are stored securely in Lair keystore

## Disclosure Policy

When we receive a security report:

1. **Acknowledge** — Confirm receipt within 48 hours
2. **Investigate** — Assess severity and impact
3. **Fix** — Develop and test a patch
4. **Notify** — Inform affected users (if applicable)
5. **Publish** — Release a security advisory

We follow **responsible disclosure**:
- We'll work with you to understand the issue
- We won't publicly disclose until a fix is available
- We'll credit you in our advisory (unless you prefer anonymity)

## Security Best Practices for Integrators

If you're integrating this DNA into your application:

### ✅ Do:
- Validate all data before storing on DHT
- Be explicit with users that signatures are public and permanent
- Verify signatures against the signer's agent public key before trusting them
- Treat revocation as a signal to check, not a guarantee of deletion
- Implement rate limiting on write operations

### ❌ Don't:
- Store PII on this DNA (use the [Private DNA](https://github.com/WeAreFlowsta/flowsta-private-dna))
- Assume a signature is valid without verifying the agent key
- Assume a revoked signature is gone — it's visible forever, with a revocation beside it
- Trust DHT data without validation
- Use v1.0 or v1.1 (deprecated)

## Vulnerability Examples

### High Severity
- Ability to forge a signature under another user's agent key
- Ability to revoke another user's signature
- DOS attacks that prevent DHT operations
- Data injection attacks that corrupt signature entries

### Medium Severity
- Information disclosure beyond public DHT design
- Validation bypass on content rights or intent fields
- Improper error handling leaking internal state

### Low Severity
- Documentation errors
- Non-exploitable edge cases
- Performance issues without security impact

## Bug Bounty

We currently don't have a formal bug bounty program, but we deeply appreciate security research and will:
- Credit you in our security advisories
- Consider compensation for critical vulnerabilities (case-by-case)
- Fast-track your contributions

## Contact

**Security Email**: security@flowsta.com
**Response Time**: 48 hours

---

**Maintained by**: [Flowsta Security Team](https://flowsta.com)
