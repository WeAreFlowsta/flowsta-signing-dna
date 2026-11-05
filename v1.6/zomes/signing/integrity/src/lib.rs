//! Flowsta Signing DNA v1.6 - integrity zome.
//!
//! v1.5's records and links, with the rules a peer checks before it holds a
//! write:
//!
//!   - a carried record (a `SignatureRecord`, `RevocationEntry` or
//!     `SignatureThumbnail` written again here from v1.4 or v1.5) carries its
//!     original exactly as its author signed it: the action's bytes, the
//!     signature over them and the entry. The checks need no network:
//!       1. the original action decodes on its own line's shape, names the
//!          carried author and time, and hashes to the carried action hash;
//!       2. the original author's signature verifies over those bytes;
//!       3. the original entry hashes to the entry the action names and is
//!          the same kind of record;
//!       4. the copy says what the original says (a revocation's or a
//!          thumbnail's signature is the copy here of the one it named);
//!   - a revocation is its signature's signer's; a thumbnail is the signer's
//!     or the signature record's author's (a carried copy's witness);
//!   - only a thumbnail is updated, by its own author; nothing is deleted and
//!     no link is removed;
//!   - every link is filed by its record's author, from the base the record
//!     names.
//!
//! Validation is written for the 0.7 action model (`FlatOp`, `TypedAction`).
use hdi::prelude::*;

// ── Carried records ──────────────────────────────────────────────────

/// The original a carried record is a copy of, as its author signed it on
/// the network it came from.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct CarriedFrom {
    /// "1.4" (Holochain 0.6) or "1.5" (0.7).
    pub original_dna: String,
    /// The record's action hash there (the key of `CarriedIndex`).
    pub original_action_hash: ActionHash,
    pub original_author: AgentPubKey,
    pub original_timestamp: Timestamp,
    /// The bytes the author signed (Holochain encodes the action and the key
    /// store signs those bytes), so no check re-encodes anything.
    #[serde(with = "serde_bytes")]
    pub original_action: Vec<u8>,
    pub original_signature: Signature,
    /// The original entry's bytes.
    #[serde(with = "serde_bytes")]
    pub original_entry: Vec<u8>,
    /// The agent that wrote the copy here (the author's own device, another
    /// device of theirs, or a node carrying an archive).
    pub witness: AgentPubKey,
    /// Reserved for the signer's device certificate chain.
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

    /// The original, when the record was carried from v1.4 or v1.5; `None`
    /// for a record signed on this network.
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

    /// The original, when carried
    pub carried_from: Option<CarriedFrom>,
}

/// A revocation of a previously created SignatureRecord.
/// The original signature remains on the DHT (immutable) but is marked as revoked.
/// Only the signature's signer writes one (a carried one proves the signer
/// wrote the original).
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
pub struct RevocationEntry {
    /// ActionHash of the original SignatureRecord creation action (on this network)
    pub signature_action: ActionHash,

    /// Unix timestamp in milliseconds when the revocation was created
    pub revoked_at: i64,

    /// Optional reason for revocation (max 280 chars)
    pub reason: Option<String>,

    /// The original, when carried
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

// ── The original record ───────────────────────────────────────────────

/// The signing zome is zome 0 on v1.4 and v1.5, with the same entry order.
pub const SIGNING_ZOME: u8 = 0;
pub const SIGNATURE_ENTRY: u8 = 0;
pub const REVOCATION_ENTRY: u8 = 1;
pub const THUMBNAIL_ENTRY: u8 = 2;

/// What the checks read of an original action, from either line.
pub struct Original {
    pub author: AgentPubKey,
    pub timestamp: Timestamp,
    pub entry_hash: EntryHash,
    pub zome_index: u8,
    pub entry_index: u8,
}

/// A Holochain 0.6 action as far as a check reads it: an enum tagged by
/// `type` (0.7 changed the action shape, so this DNA has no 0.6 `Action`).
/// An Update names its entry the same way (a thumbnail's latest version).
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum Action06 {
    Create(Create06),
    Update(Create06),
    #[serde(other)]
    Other,
}

#[derive(Deserialize, Debug)]
struct Create06 {
    author: AgentPubKey,
    timestamp: Timestamp,
    entry_type: EntryType,
    entry_hash: EntryHash,
}

/// Decode the original action on its own line's shape.
pub fn original_of(c: &CarriedFrom) -> Result<Original, String> {
    let (author, timestamp, entry_type, entry_hash) = match c.original_dna.as_str() {
        "1.4" => match holochain_serialized_bytes::decode::<_, Action06>(&c.original_action) {
            Ok(Action06::Create(a) | Action06::Update(a)) => (a.author, a.timestamp, a.entry_type, a.entry_hash),
            Ok(Action06::Other) => return Err("the original action writes no entry".to_string()),
            Err(e) => return Err(format!("the original action does not decode: {e}")),
        },
        "1.5" => {
            let a: Action = holochain_serialized_bytes::decode(&c.original_action)
                .map_err(|e| format!("the original action does not decode: {e}"))?;
            if !matches!(a.data, ActionData::Create(_) | ActionData::Update(_)) {
                return Err("the original action writes no entry".to_string());
            }
            let Some((hash, kind)) = a.entry_data() else {
                return Err("the original action carries no entry".to_string());
            };
            (a.author().clone(), a.timestamp(), kind.clone(), hash.clone())
        }
        other => return Err(format!("records are not carried from DNA {other}")),
    };
    let EntryType::App(def) = entry_type else {
        return Err("the original is not an app entry".to_string());
    };
    Ok(Original { author, timestamp, entry_hash, zome_index: def.zome_index.0, entry_index: def.entry_index.0 })
}

/// Steps 1-3 for a carried record whose original must be entry `entry_index`
/// of the signing zome, written here by `author`. `Err` is why it is invalid.
pub fn check_carried(c: &CarriedFrom, author: &AgentPubKey, entry_index: u8) -> ExternResult<Result<(), String>> {
    if &c.witness != author {
        return Ok(Err("a carried record's witness is the agent that writes it".to_string()));
    }
    if c.certificate.as_ref().is_some_and(|b| b.len() > 4096) {
        return Ok(Err("certificate must be 4096 bytes or less".to_string()));
    }
    let original = match original_of(c) {
        Ok(o) => o,
        Err(e) => return Ok(Err(e)),
    };
    if original.author != c.original_author || original.timestamp != c.original_timestamp {
        return Ok(Err("the original action names another author or time".to_string()));
    }
    let hashed = ActionHash::from_raw_32(holo_hash::encode::blake2b_256(&c.original_action));
    if hashed != c.original_action_hash {
        return Ok(Err("the original action does not hash to the carried action hash".to_string()));
    }
    if !verify_signature_raw(c.original_author.clone(), c.original_signature.clone(), c.original_action.clone())? {
        return Ok(Err("the original author's signature does not verify".to_string()));
    }
    let entry = Entry::App(AppEntryBytes(SerializedBytes::from(UnsafeBytes::from(c.original_entry.clone()))));
    if hash_entry(entry)? != original.entry_hash {
        return Ok(Err("the original entry does not hash to the entry the action names".to_string()));
    }
    if (original.zome_index, original.entry_index) != (SIGNING_ZOME, entry_index) {
        return Ok(Err("the original is another kind of record".to_string()));
    }
    Ok(Ok(()))
}

/// The original entry's fields (v1.4 wrote them without `carried_from`;
/// v1.5's is ignored here).
#[derive(Deserialize, Debug, PartialEq)]
pub struct SignatureFields {
    pub file_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer: AgentPubKey,
    pub signed_at: i64,
    pub intent: Option<SigningIntent>,
    pub ai_generation: Option<AiGeneration>,
    pub content_rights: Option<ContentRights>,
    pub integrity_report: Option<IntegrityReport>,
    pub perceptual_hash: Option<PerceptualHash>,
    pub supersedes: Option<ActionHash>,
    pub expires_at: Option<i64>,
    pub tags: Option<Vec<String>>,
    pub comment: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct RevocationFields {
    pub signature_action: ActionHash,
    pub revoked_at: i64,
    pub reason: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct ThumbnailFields {
    pub signature_action: ActionHash,
    pub thumbnail: String,
    pub updated_at: i64,
}

pub fn original_fields<T: serde::de::DeserializeOwned + std::fmt::Debug>(c: &CarriedFrom) -> Result<T, String> {
    holochain_serialized_bytes::decode(&c.original_entry).map_err(|e| format!("the original entry does not decode: {e}"))
}

impl SignatureRecord {
    fn fields(&self) -> SignatureFields {
        SignatureFields {
            file_hash: self.file_hash.clone(),
            signature: self.signature.clone(),
            signer: self.signer.clone(),
            signed_at: self.signed_at,
            intent: self.intent.clone(),
            ai_generation: self.ai_generation.clone(),
            content_rights: self.content_rights.clone(),
            integrity_report: self.integrity_report.clone(),
            perceptual_hash: self.perceptual_hash.clone(),
            supersedes: self.supersedes.clone(),
            expires_at: self.expires_at,
            tags: self.tags.clone(),
            comment: self.comment.clone(),
        }
    }
}

/// The signature record `signature_action` names here.
fn signature_here(signature_action: &ActionHash) -> ExternResult<Option<(AgentPubKey, SignatureRecord)>> {
    let record = must_get_valid_record(signature_action.clone())?;
    let author = record.action().author().clone();
    Ok(record.entry().to_app_option::<SignatureRecord>().ok().flatten().map(|s| (author, s)))
}

/// Whether the copy here (`copy`) of a signature is the one whose original
/// was `original` (a revocation's or thumbnail's original named the old hash).
fn is_copy_of(copy: &SignatureRecord, original: &ActionHash) -> bool {
    copy.carried_from.as_ref().is_some_and(|c| &c.original_action_hash == original)
}

// ── Validation ──────────────────────────────────────────────────────

fn invalid(reason: impl Into<String>) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Invalid(reason.into()))
}

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
            OpEntry::UpdateEntry { app_entry, action, .. } => match app_entry {
                EntryTypes::SignatureThumbnail(entry) => {
                    let author = action.author().clone();
                    if entry.carried_from.is_some() {
                        return invalid("A carried thumbnail is written new, not as an update");
                    }
                    validate_signature_thumbnail(&entry, &author)
                }
                _ => invalid("Only a thumbnail is updated"),
            },
            _ => Ok(ValidateCallbackResult::Valid),
        },
        // An update's original side: a thumbnail, by its own author.
        FlatOp::Update(OpUpdate::Entry { action, .. }) | FlatOp::CreateRecord(OpRecord::UpdateEntry { action, .. }) => {
            let original = must_get_valid_record(action.data.original_action_address.clone())?;
            let is_thumbnail = original.entry().to_app_option::<SignatureThumbnail>().ok().flatten().is_some();
            if !is_thumbnail {
                return invalid("Only a thumbnail is updated");
            }
            if original.action().author() != action.author() {
                return invalid("Only a thumbnail's author updates it");
            }
            Ok(ValidateCallbackResult::Valid)
        }
        FlatOp::Delete(_) | FlatOp::CreateRecord(OpRecord::DeleteEntry { .. }) => invalid("Records here are never deleted"),
        FlatOp::Link(OpLink::CreateLink { link_type, action }) => {
            validate_create_link(&link_type, &action.data.base_address, &action.data.target_address, action.author())
        }
        FlatOp::Link(OpLink::DeleteLink { .. }) => invalid("Links here are never removed"),
        _ => Ok(ValidateCallbackResult::Valid),
    }
}

/// A SignatureRecord:
/// 1. native: signed by the committing agent; carried: the original checks
///    (steps 1-3), is a SignatureRecord saying what the copy says, and the
///    signer is its author
/// 2. file_hash 32 bytes, signature 64 bytes, and the signature verifies over
///    file_hash against the signer
/// 3. signed_at positive, and the field limits
fn validate_signature_record(entry: &SignatureRecord, author: &AgentPubKey) -> ExternResult<ValidateCallbackResult> {
    match &entry.carried_from {
        None => {
            if &entry.signer != author {
                return invalid("signer must match the committing agent");
            }
        }
        Some(from) => {
            if let Err(e) = check_carried(from, author, SIGNATURE_ENTRY)? {
                return invalid(e);
            }
            let original: SignatureFields = match original_fields(from) {
                Ok(f) => f,
                Err(e) => return invalid(e),
            };
            if original != entry.fields() {
                return invalid("A carried signature must say what its original says");
            }
            if from.original_author != entry.signer {
                return invalid("a carried signature's signer must be its original author");
            }
        }
    }

    if entry.file_hash.len() != 32 {
        return invalid(format!("file_hash must be exactly 32 bytes, got {}", entry.file_hash.len()));
    }
    if entry.signature.len() != 64 {
        return invalid(format!("signature must be exactly 64 bytes, got {}", entry.signature.len()));
    }
    // The proof of the signature itself, native or carried; it needs no
    // network. verify_signature_raw avoids MessagePack re-encoding.
    let sig = Signature::from(
        <[u8; 64]>::try_from(entry.signature.as_slice()).map_err(|_| wasm_error!("Failed to convert signature to [u8; 64]"))?,
    );
    if !verify_signature_raw(entry.signer.clone(), sig, entry.file_hash.clone())? {
        return invalid("Ed25519 signature does not verify against file_hash and signer");
    }
    if entry.signed_at <= 0 {
        return invalid("signed_at must be a positive timestamp");
    }
    if let Some(ref report) = entry.integrity_report {
        if report.issues_found.iter().any(|i| i.description.len() > 200) {
            return invalid("integrity issue description must be 200 chars or less");
        }
    }
    if let Some(ContentRights { license: Some(License::Custom(ref s)), .. }) = entry.content_rights {
        if s.len() > 128 {
            return invalid("Custom license string must be 128 chars or less");
        }
    }
    if let Some(ref tags) = entry.tags {
        if tags.len() > 5 {
            return invalid("Maximum 5 tags per signature");
        }
        if tags.iter().any(|t| t.len() > 32) {
            return invalid("Each tag must be 32 chars or less");
        }
    }
    if entry.comment.as_ref().is_some_and(|c| c.len() > 280) {
        return invalid("Comment must be 280 chars or less");
    }
    Ok(ValidateCallbackResult::Valid)
}

/// A RevocationEntry is its signature's signer's: native, written by the
/// signer; carried, the original was written by the signer of the signature
/// it named, and the copy names that signature's copy here.
fn validate_revocation_entry(entry: &RevocationEntry, author: &AgentPubKey) -> ExternResult<ValidateCallbackResult> {
    if entry.reason.as_ref().is_some_and(|r| r.len() > 280) {
        return invalid("revocation reason must be 280 chars or less");
    }
    let Some((_, signature)) = signature_here(&entry.signature_action)? else {
        return invalid("A revocation names a signature record");
    };
    match &entry.carried_from {
        None => {
            if &signature.signer != author {
                return invalid("Only the signer revokes a signature");
            }
        }
        Some(from) => {
            if let Err(e) = check_carried(from, author, REVOCATION_ENTRY)? {
                return invalid(e);
            }
            let original: RevocationFields = match original_fields(from) {
                Ok(f) => f,
                Err(e) => return invalid(e),
            };
            if original.revoked_at != entry.revoked_at || original.reason != entry.reason {
                return invalid("A carried revocation must say what its original says");
            }
            if !is_copy_of(&signature, &original.signature_action) {
                return invalid("A carried revocation names the copy here of the signature its original named");
            }
            if from.original_author != signature.signer {
                return invalid("Only the signer revokes a signature");
            }
        }
    }
    Ok(ValidateCallbackResult::Valid)
}

/// A SignatureThumbnail: a data:image/ URI of 15 KB or less, by the
/// signature's signer or the signature record's author; a carried one says
/// what its original says and names the copy here of its signature.
fn validate_signature_thumbnail(entry: &SignatureThumbnail, author: &AgentPubKey) -> ExternResult<ValidateCallbackResult> {
    if !entry.thumbnail.starts_with("data:image/") {
        return invalid("thumbnail must be a data:image/ URI");
    }
    if entry.thumbnail.len() > 15_000 {
        return invalid(format!("thumbnail must be 15KB or less, got {} bytes", entry.thumbnail.len()));
    }
    let Some((signature_author, signature)) = signature_here(&entry.signature_action)? else {
        return invalid("A thumbnail names a signature record");
    };
    match &entry.carried_from {
        None => {
            if author != &signature.signer && author != &signature_author {
                return invalid("A thumbnail is written by the signature's signer or its record's author");
            }
        }
        Some(from) => {
            if let Err(e) = check_carried(from, author, THUMBNAIL_ENTRY)? {
                return invalid(e);
            }
            let original: ThumbnailFields = match original_fields(from) {
                Ok(f) => f,
                Err(e) => return invalid(e),
            };
            if original.thumbnail != entry.thumbnail || original.updated_at != entry.updated_at {
                return invalid("A carried thumbnail must say what its original says");
            }
            if !is_copy_of(&signature, &original.signature_action) {
                return invalid("A carried thumbnail names the copy here of the signature its original named");
            }
        }
    }
    Ok(ValidateCallbackResult::Valid)
}

/// The base a file hash's links start from (the coordinator's
/// `hash_to_36_bytes`).
pub fn file_hash_base(file_hash: &[u8]) -> ExternalHash {
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(&[0x84, 0x24, 0x24]);
    bytes.extend_from_slice(file_hash);
    bytes.push(0x00);
    ExternalHash::from_raw_36(bytes)
}

/// The base a perceptual band's links start from (`hash_to_36_bytes_padded`).
pub fn band_base(band: &[u8]) -> ExternalHash {
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(&[0x84, 0x24, 0x24]);
    bytes.extend_from_slice(&band[..band.len().min(32)]);
    while bytes.len() < 36 {
        bytes.push(0x00);
    }
    ExternalHash::from_raw_36(bytes)
}

/// Every link is filed by the author of the record it points at, from the
/// base that record names.
fn validate_create_link(link_type: &LinkTypes, base: &AnyLinkableHash, target: &AnyLinkableHash, author: &AgentPubKey) -> ExternResult<ValidateCallbackResult> {
    let Some(target) = target.clone().into_action_hash() else {
        return invalid("A link here points at a record");
    };
    let record = must_get_valid_record(target)?;
    if record.action().author() != author {
        return invalid("A record is filed by its own author");
    }
    let entry = record.entry();
    let from = |b: AnyLinkableHash| *base == b;
    let ok = match link_type {
        LinkTypes::FileHashToSignature => entry
            .to_app_option::<SignatureRecord>()
            .ok()
            .flatten()
            .is_some_and(|s| from(file_hash_base(&s.file_hash).into())),
        LinkTypes::AgentToSignature => entry
            .to_app_option::<SignatureRecord>()
            .ok()
            .flatten()
            .is_some_and(|s| from(AgentPubKey::from_raw_32(s.signer.get_raw_32().to_vec()).into())),
        LinkTypes::PerceptualBandToSignature => entry
            .to_app_option::<SignatureRecord>()
            .ok()
            .flatten()
            .and_then(|s| s.perceptual_hash)
            .is_some_and(|p| p.bands.iter().any(|b| from(band_base(b).into()))),
        LinkTypes::SignatureToRevocation => entry
            .to_app_option::<RevocationEntry>()
            .ok()
            .flatten()
            .is_some_and(|r| from(r.signature_action.into())),
        LinkTypes::SignatureToThumbnail => entry
            .to_app_option::<SignatureThumbnail>()
            .ok()
            .flatten()
            .is_some_and(|t| from(t.signature_action.into())),
        LinkTypes::CarriedIndex => {
            let carried = entry
                .to_app_option::<SignatureRecord>()
                .ok()
                .flatten()
                .and_then(|s| s.carried_from)
                .or_else(|| entry.to_app_option::<RevocationEntry>().ok().flatten().and_then(|r| r.carried_from))
                .or_else(|| entry.to_app_option::<SignatureThumbnail>().ok().flatten().and_then(|t| t.carried_from));
            carried.is_some_and(|c| from(carried_base(&c.original_action_hash).into()))
        }
    };
    if ok {
        Ok(ValidateCallbackResult::Valid)
    } else {
        invalid("A link is filed from the base its record names")
    }
}
