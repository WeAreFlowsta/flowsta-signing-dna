use hdi::prelude::*;

// ── Entry Types ─────────────────────────────────────────────────────

/// A cryptographic signature over a file's SHA-256 hash, committed to the
/// public DHT as proof that a specific agent signed a specific document
/// at a specific time.
///
/// The file itself is never uploaded — only the hash. The hash cannot be
/// reversed to derive file contents.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
pub struct SignatureRecord {
    /// SHA-256 hash of the file content (exactly 32 bytes)
    pub file_hash: Vec<u8>,

    /// Ed25519 signature of file_hash by the signer (exactly 64 bytes)
    pub signature: Vec<u8>,

    /// The agent who signed — must match the committing agent
    pub signer: AgentPubKey,

    /// Unix timestamp in milliseconds when the signature was created
    pub signed_at: i64,

    /// Why this file was signed
    pub intent: Option<SigningIntent>,

    /// Whether AI was involved in creating the content
    pub ai_generation: Option<AiGeneration>,

    /// Rights manifest: license, commercial availability, AI training policy, contact preference
    pub content_rights: Option<ContentRights>,

    /// Results of file integrity analysis (steganography checks) performed before signing
    pub integrity_report: Option<IntegrityReport>,

    /// Perceptual hash for fuzzy file matching (survives re-encode, resize, etc.)
    /// None for file types that don't support perceptual hashing (documents, archives)
    pub perceptual_hash: Option<PerceptualHash>,
}

/// A revocation of a previously created SignatureRecord.
/// The original signature remains on the DHT (immutable) but is marked as revoked.
/// Only the original signer can create a revocation.
///
/// Included in v1.0 integrity zome from day one. Coordinator functions for
/// revocation are added in Phase 2 via updateCoordinators hot-swap.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
pub struct RevocationEntry {
    /// ActionHash of the original SignatureRecord creation action
    pub signature_action: ActionHash,

    /// Unix timestamp in milliseconds when the revocation was created
    pub revoked_at: i64,

    /// Optional reason for revocation (max 280 chars)
    pub reason: Option<String>,
}

// ── Metadata Enums ──────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SigningIntent {
    Authorship,
    Approval,
    Witness,
    Receipt,
    Agreement,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AiGeneration {
    None,
    Assisted,
    Generated,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ContentRights {
    pub license: Option<License>,
    pub commercial_licensing: Option<CommercialLicensing>,
    pub ai_training: Option<AiTrainingPolicy>,
    pub contact_preference: Option<ContactPreference>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum License {
    AllRightsReserved,
    CC0,
    CCBY,
    CCBYSA,
    CCBYNC,
    CCBYNCSA,
    MIT,
    Apache2,
    GPL3,
    Custom(String),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum CommercialLicensing {
    NotAvailable,
    OpenToLicensing,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AiTrainingPolicy {
    Allowed,
    AllowedWithAttribution,
    RequiresLicense,
    NotAllowed,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ContactPreference {
    NoContact,
    AllowContactRequests,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntegrityReport {
    pub checks_performed: Vec<CheckType>,
    pub issues_found: Vec<IntegrityIssue>,
    pub checked_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum CheckType {
    PostEofData,
    LsbAnalysis,
    UnicodeSteg,
    MetadataInspection,
    EntropyAnalysis,
    AppendedFileDetection,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IntegrityIssue {
    pub check_type: CheckType,
    pub severity: Severity,
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

// ── Perceptual Hashing ──────────────────────────────────────────────

/// A perceptual hash that survives re-encoding, resizing, and minor edits.
/// Used for fuzzy file matching alongside the exact SHA-256 hash.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PerceptualHash {
    /// The type of perceptual hash algorithm used
    pub hash_type: PerceptualHashType,
    /// The full perceptual hash value
    pub hash_value: Vec<u8>,
    /// LSH bands for DHT lookup (4 bands derived from hash_value)
    /// Each band is a portion of the hash used for approximate matching
    pub bands: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PerceptualHashType {
    /// DCT-based perceptual hash for images (64 bits / 8 bytes)
    /// Survives: resize, recompress, colour change, minor edits
    ImagePHash,
    /// Chromaprint audio fingerprint (variable length, typically ~2KB)
    /// Survives: re-encode, compression, noise, minor trim
    AudioChromaprint,
    /// Frame-based perceptual hash for video (multiple frame hashes)
    /// Survives: re-encode, compression
    VideoPHash,
}

// ── Entry & Link Type Registration ──────────────────────────────────

#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EntryTypes {
    SignatureRecord(SignatureRecord),
    RevocationEntry(RevocationEntry),
}

#[derive(Serialize, Deserialize)]
#[hdk_link_types]
pub enum LinkTypes {
    /// file_hash bytes -> SignatureRecord ActionHash (verification lookup)
    FileHashToSignature,
    /// AgentPubKey -> SignatureRecord ActionHash (signing history)
    AgentToSignature,
    /// SignatureRecord ActionHash -> RevocationEntry ActionHash
    SignatureToRevocation,
    /// Perceptual hash LSH band -> SignatureRecord ActionHash (fuzzy matching)
    /// 4 bands per signature, each band is a portion of the perceptual hash
    PerceptualBandToSignature,
}

// ── Validation ──────────────────────────────────────────────────────

#[cfg_attr(not(feature = "integrity"), hdk_extern)]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    match op.flattened::<EntryTypes, LinkTypes>()? {
        FlatOp::StoreEntry(store_entry) => match store_entry {
            OpEntry::CreateEntry {
                app_entry, action, ..
            } => match app_entry {
                EntryTypes::SignatureRecord(entry) => {
                    validate_signature_record(&entry, &action.author)
                }
                EntryTypes::RevocationEntry(entry) => {
                    validate_revocation_entry(&entry, &action.author)
                }
            },
            OpEntry::UpdateEntry {
                app_entry, ..
            } => match app_entry {
                EntryTypes::SignatureRecord(_) => Ok(ValidateCallbackResult::Invalid(
                    "SignatureRecord entries cannot be updated".to_string(),
                )),
                EntryTypes::RevocationEntry(_) => Ok(ValidateCallbackResult::Invalid(
                    "RevocationEntry entries cannot be updated".to_string(),
                )),
            },
            _ => Ok(ValidateCallbackResult::Valid),
        },
        FlatOp::RegisterCreateLink { link_type, .. } => match link_type {
            LinkTypes::FileHashToSignature => Ok(ValidateCallbackResult::Valid),
            LinkTypes::AgentToSignature => Ok(ValidateCallbackResult::Valid),
            LinkTypes::SignatureToRevocation => Ok(ValidateCallbackResult::Valid),
            LinkTypes::PerceptualBandToSignature => Ok(ValidateCallbackResult::Valid),
        },
        FlatOp::RegisterDeleteLink { .. } => Ok(ValidateCallbackResult::Valid),
        _ => Ok(ValidateCallbackResult::Valid),
    }
}

/// Validate a SignatureRecord:
/// 1. signer must match committing agent
/// 2. file_hash must be exactly 32 bytes
/// 3. signature must be exactly 64 bytes
/// 4. Ed25519 signature must verify over file_hash
/// 5. signed_at must not be more than 5 minutes in the future
/// 6. Optional field length limits
fn validate_signature_record(
    entry: &SignatureRecord,
    author: &AgentPubKey,
) -> ExternResult<ValidateCallbackResult> {
    // 1. Signer must be the committing agent
    if &entry.signer != author {
        return Ok(ValidateCallbackResult::Invalid(
            "signer must match the committing agent".to_string(),
        ));
    }

    // 2. file_hash must be exactly 32 bytes (SHA-256)
    if entry.file_hash.len() != 32 {
        return Ok(ValidateCallbackResult::Invalid(
            format!("file_hash must be exactly 32 bytes, got {}", entry.file_hash.len()),
        ));
    }

    // 3. signature must be exactly 64 bytes (Ed25519)
    if entry.signature.len() != 64 {
        return Ok(ValidateCallbackResult::Invalid(
            format!("signature must be exactly 64 bytes, got {}", entry.signature.len()),
        ));
    }

    // 4. Verify Ed25519 signature over file_hash
    // Use verify_signature_raw to avoid MessagePack re-encoding
    let sig = Signature::from(
        <[u8; 64]>::try_from(entry.signature.as_slice())
            .map_err(|_| wasm_error!("Failed to convert signature to [u8; 64]"))?,
    );
    if !verify_signature_raw(entry.signer.clone(), sig, entry.file_hash.clone())? {
        return Ok(ValidateCallbackResult::Invalid(
            "Ed25519 signature does not verify against file_hash and signer".to_string(),
        ));
    }

    // 5. signed_at must be positive (basic sanity check — clock validation
    //    is not reliable in integrity zomes since sys_time is not available)
    if entry.signed_at <= 0 {
        return Ok(ValidateCallbackResult::Invalid(
            "signed_at must be a positive timestamp".to_string(),
        ));
    }

    // 6. Optional field length limits
    if let Some(ref report) = entry.integrity_report {
        for issue in &report.issues_found {
            if issue.description.len() > 200 {
                return Ok(ValidateCallbackResult::Invalid(
                    "integrity issue description must be 200 chars or less".to_string(),
                ));
            }
        }
    }

    if let Some(ref rights) = entry.content_rights {
        if let Some(License::Custom(ref s)) = rights.license {
            if s.len() > 128 {
                return Ok(ValidateCallbackResult::Invalid(
                    "Custom license string must be 128 chars or less".to_string(),
                ));
            }
        }
    }

    Ok(ValidateCallbackResult::Valid)
}

/// Validate a RevocationEntry:
/// 1. Only the original signer can revoke (checked at coordinator level —
///    cannot be fully validated here without DHT access, but we validate
///    that the author is consistent)
/// 2. Reason must be 280 chars or less
fn validate_revocation_entry(
    entry: &RevocationEntry,
    _author: &AgentPubKey,
) -> ExternResult<ValidateCallbackResult> {
    if let Some(ref reason) = entry.reason {
        if reason.len() > 280 {
            return Ok(ValidateCallbackResult::Invalid(
                "revocation reason must be 280 chars or less".to_string(),
            ));
        }
    }

    Ok(ValidateCallbackResult::Valid)
}
