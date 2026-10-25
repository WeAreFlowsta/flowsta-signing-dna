//! Flowsta Signing DNA v1.5 - integrity zome.
//!
//! The Holochain 0.7 generation of v1.4: the same entry and link types, with
//! one addition that lets the public record move between networks without
//! waiting for its authors:
//!
//!   - a `SignatureRecord`, `RevocationEntry` or `SignatureThumbnail` may
//!     carry its origin (`CarriedFrom`): who wrote it on the previous
//!     network, when, under which action hash, the signed action as it was,
//!     and the agent that re-published it here (the witness);
//!   - a `CarriedIndex` link from the old action hash to the new one, so a
//!     record is carried once and a late author's own carry finds it.
//!
//! The proof of a signature is the person's Ed25519 signature over the file
//! hash, embedded in the entry; it verifies against the signer's key on any
//! network. A carried signature is therefore as good as a native one: the
//! validation below checks that embedded signature the same way for both,
//! and for a carried record also requires the witness to be the committing
//! agent and the signer to be the original author.
//!
//! Validation is written for the 0.7 action model (`FlatOp::CreateEntry`,
//! `FlatOp::Link`, actions as `TypedAction`).
use hdi::prelude::*;

// ── Carried records ──────────────────────────────────────────────────

/// What a carried record keeps of its origin, so a reader on this network
/// can check it without the network it came from.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct CarriedFrom {
    /// The agent that authored the record on the previous network.
    pub original_author: AgentPubKey,
    /// The action's timestamp there (Unix ms).
    pub original_timestamp: i64,
    /// The record's action hash there (the key of `CarriedIndex`).
    pub original_action_hash: ActionHash,
    /// MessagePack of the original `SignedActionHashed`, when the carrier
    /// held it; `None` for records carried from a network it could no longer
    /// read. Required for carried revocations and thumbnails, whose only
    /// proof of authorship is that signed action.
    pub original_signed_action: Option<Vec<u8>>,
    /// The agent that re-published the record here (the author's own device
    /// migrating, or a node carrying an archive): the record's author on
    /// this network.
    pub witness: AgentPubKey,
    /// Reserved for the signer's device certificate chain (empty until the
    /// identity network issues certificates).
    pub certificate: Option<Vec<u8>>,
}

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

    /// The agent who signed — the committing agent for a native record, the
    /// original author for a carried one
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

    // ── v1.3 metadata extensions ───────────────────────────────────

    /// ActionHash of a previous signature this one replaces (version chain)
    pub supersedes: Option<ActionHash>,

    /// Optional expiry timestamp (Unix ms). Signature is still valid after
    /// expiry but verifiers can check and display the expiry status.
    pub expires_at: Option<i64>,

    /// Searchable tags (max 5, each max 32 chars)
    pub tags: Option<Vec<String>>,

    /// Signer's note about this signature (max 280 chars)
    pub comment: Option<String>,

    // ── v1.5 ───────────────────────────────────────────────────────

    /// Where the record came from when it was carried from the previous
    /// network; `None` for a record signed on this one.
    pub carried_from: Option<CarriedFrom>,
}

/// A thumbnail image for a SignatureRecord.
/// Stored as a separate entry so it can be updated independently
/// without affecting the immutable cryptographic signature.
///
/// Auto-generated from the signed file (images: resize, video: first frame,
/// audio: waveform, documents: first page). Users can replace with a custom thumbnail.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
pub struct SignatureThumbnail {
    /// ActionHash of the SignatureRecord this thumbnail belongs to (on this network)
    pub signature_action: ActionHash,

    /// Base64 data URI of the thumbnail image (JPEG, max ~10KB)
    /// Format: "data:image/jpeg;base64,/9j/4AAQ..."
    pub thumbnail: String,

    /// Unix timestamp in milliseconds
    pub updated_at: i64,

    /// v1.5: origin when carried
    pub carried_from: Option<CarriedFrom>,
}

/// A revocation of a previously created SignatureRecord.
/// The original signature remains on the DHT (immutable) but is marked as revoked.
/// Only the original signer can create a revocation (a carried revocation
/// proves that through its original signed action).
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
pub struct RevocationEntry {
    /// ActionHash of the original SignatureRecord creation action (on this network)
    pub signature_action: ActionHash,

    /// Unix timestamp in milliseconds when the revocation was created
    pub revoked_at: i64,

    /// Optional reason for revocation (max 280 chars)
    pub reason: Option<String>,

    /// v1.5: origin when carried
    pub carried_from: Option<CarriedFrom>,
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
    SignatureThumbnail(SignatureThumbnail),
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
    /// SignatureRecord ActionHash -> SignatureThumbnail ActionHash
    SignatureToThumbnail,
    /// v1.5: the record's action hash on the previous network (as an
    /// ExternalHash, `carried_base`) -> its ActionHash here
    CarriedIndex,
}

/// The link base a carried record is indexed under: the old action hash's
/// 32 core bytes as an ExternalHash (its DHT location belonged to another
/// network, so it is not used as a hash here).
pub fn carried_base(original_action_hash: &ActionHash) -> ExternalHash {
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(&[0x84, 0x24, 0x24]);
    bytes.extend_from_slice(original_action_hash.get_raw_32());
    bytes.push(0x00);
    ExternalHash::from_raw_36(bytes)
}

// ── Validation ──────────────────────────────────────────────────────

#[cfg_attr(not(feature = "integrity"), hdk_extern)]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    match op.flattened::<EntryTypes, LinkTypes>()? {
        FlatOp::CreateEntry(op_entry) => match op_entry {
            OpEntry::CreateEntry { app_entry, action } => {
                let author = action.author().clone();
                match app_entry {
                    EntryTypes::SignatureRecord(entry) => validate_signature_record(&entry, &author),
                    EntryTypes::RevocationEntry(entry) => validate_revocation_entry(&entry, &author),
                    EntryTypes::SignatureThumbnail(entry) => validate_signature_thumbnail(&entry, &author),
                }
            }
            OpEntry::UpdateEntry { app_entry, action, .. } => {
                let author = action.author().clone();
                match app_entry {
                    EntryTypes::SignatureRecord(_) => Ok(ValidateCallbackResult::Invalid(
                        "SignatureRecord entries cannot be updated".to_string(),
                    )),
                    EntryTypes::RevocationEntry(_) => Ok(ValidateCallbackResult::Invalid(
                        "RevocationEntry entries cannot be updated".to_string(),
                    )),
                    // Thumbnails CAN be updated (user can replace with custom image)
                    EntryTypes::SignatureThumbnail(entry) => validate_signature_thumbnail(&entry, &author),
                }
            }
            _ => Ok(ValidateCallbackResult::Valid),
        },
        FlatOp::Link(OpLink::CreateLink { link_type, .. }) => match link_type {
            LinkTypes::FileHashToSignature => Ok(ValidateCallbackResult::Valid),
            LinkTypes::AgentToSignature => Ok(ValidateCallbackResult::Valid),
            LinkTypes::SignatureToRevocation => Ok(ValidateCallbackResult::Valid),
            LinkTypes::PerceptualBandToSignature => Ok(ValidateCallbackResult::Valid),
            LinkTypes::SignatureToThumbnail => Ok(ValidateCallbackResult::Valid),
            LinkTypes::CarriedIndex => Ok(ValidateCallbackResult::Valid),
        },
        FlatOp::Link(OpLink::DeleteLink { .. }) => Ok(ValidateCallbackResult::Valid),
        _ => Ok(ValidateCallbackResult::Valid),
    }
}

/// A carried record: the witness is the committing agent, the origin names
/// a positive time, and (where `signed_action_required`) the original
/// signed action is present, since nothing else proves who authored a
/// revocation or a thumbnail on the previous network.
fn validate_carried_from(
    from: &CarriedFrom,
    author: &AgentPubKey,
    signed_action_required: bool,
) -> Option<String> {
    if &from.witness != author {
        return Some("a carried record's witness must be the committing agent".to_string());
    }
    if from.original_timestamp <= 0 {
        return Some("original_timestamp must be a positive timestamp".to_string());
    }
    if signed_action_required && from.original_signed_action.is_none() {
        return Some("a carried revocation or thumbnail must carry its original signed action".to_string());
    }
    if let Some(ref sa) = from.original_signed_action {
        if sa.is_empty() || sa.len() > 4096 {
            return Some("original_signed_action must be 1 to 4096 bytes".to_string());
        }
    }
    if let Some(ref c) = from.certificate {
        if c.len() > 4096 {
            return Some("certificate must be 4096 bytes or less".to_string());
        }
    }
    None
}

/// Validate a SignatureRecord:
/// 1. native: signer must match the committing agent;
///    carried: the witness is the committing agent and the signer is the original author
/// 2. file_hash must be exactly 32 bytes
/// 3. signature must be exactly 64 bytes
/// 4. Ed25519 signature must verify over file_hash against the signer (native or carried)
/// 5. signed_at must be positive
/// 6. Optional field length limits
fn validate_signature_record(
    entry: &SignatureRecord,
    author: &AgentPubKey,
) -> ExternResult<ValidateCallbackResult> {
    // 1. Who may commit this record
    match &entry.carried_from {
        None => {
            if &entry.signer != author {
                return Ok(ValidateCallbackResult::Invalid(
                    "signer must match the committing agent".to_string(),
                ));
            }
        }
        Some(from) => {
            if let Some(reason) = validate_carried_from(from, author, false) {
                return Ok(ValidateCallbackResult::Invalid(reason));
            }
            if from.original_author != entry.signer {
                return Ok(ValidateCallbackResult::Invalid(
                    "a carried signature's signer must be its original author".to_string(),
                ));
            }
        }
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

    // 4. Verify Ed25519 signature over file_hash against the signer. This is
    //    the proof, native or carried; it needs no network.
    //    Use verify_signature_raw to avoid MessagePack re-encoding.
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

    // 7. v1.3 field limits
    if let Some(ref tags) = entry.tags {
        if tags.len() > 5 {
            return Ok(ValidateCallbackResult::Invalid(
                "Maximum 5 tags per signature".to_string(),
            ));
        }
        for tag in tags {
            if tag.len() > 32 {
                return Ok(ValidateCallbackResult::Invalid(
                    "Each tag must be 32 chars or less".to_string(),
                ));
            }
        }
    }

    if let Some(ref comment) = entry.comment {
        if comment.len() > 280 {
            return Ok(ValidateCallbackResult::Invalid(
                "Comment must be 280 chars or less".to_string(),
            ));
        }
    }

    Ok(ValidateCallbackResult::Valid)
}

/// Validate a RevocationEntry:
/// 1. Only the original signer can revoke (checked at coordinator level —
///    cannot be fully validated here without DHT access); a carried
///    revocation must carry its original signed action, which is the proof
/// 2. Reason must be 280 chars or less
fn validate_revocation_entry(
    entry: &RevocationEntry,
    author: &AgentPubKey,
) -> ExternResult<ValidateCallbackResult> {
    if let Some(ref from) = entry.carried_from {
        if let Some(reason) = validate_carried_from(from, author, true) {
            return Ok(ValidateCallbackResult::Invalid(reason));
        }
    }
    if let Some(ref reason) = entry.reason {
        if reason.len() > 280 {
            return Ok(ValidateCallbackResult::Invalid(
                "revocation reason must be 280 chars or less".to_string(),
            ));
        }
    }

    Ok(ValidateCallbackResult::Valid)
}

/// Validate a SignatureThumbnail:
/// 1. Thumbnail must be a data URI (starts with "data:image/")
/// 2. Thumbnail must be 15KB or less (base64 encoded)
/// 3. A carried thumbnail carries its original signed action
fn validate_signature_thumbnail(
    entry: &SignatureThumbnail,
    author: &AgentPubKey,
) -> ExternResult<ValidateCallbackResult> {
    if let Some(ref from) = entry.carried_from {
        if let Some(reason) = validate_carried_from(from, author, true) {
            return Ok(ValidateCallbackResult::Invalid(reason));
        }
    }
    if !entry.thumbnail.starts_with("data:image/") {
        return Ok(ValidateCallbackResult::Invalid(
            "thumbnail must be a data:image/ URI".to_string(),
        ));
    }

    // ~15KB base64 limit (~11KB decoded image)
    if entry.thumbnail.len() > 15_000 {
        return Ok(ValidateCallbackResult::Invalid(
            format!("thumbnail must be 15KB or less, got {} bytes", entry.thumbnail.len()),
        ));
    }

    Ok(ValidateCallbackResult::Valid)
}
