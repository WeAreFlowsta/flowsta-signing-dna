use hdk::prelude::*;
use signing_integrity::*;

#[hdk_dependent_entry_types]
enum EntryZomes {
    IntegritySigning(signing_integrity::EntryTypes),
}

// ── Input Types ─────────────────────────────────────────────────────

/// Input for revoke_signature (Phase 2 — coordinator function added via hot-swap)
#[derive(Serialize, Deserialize, Debug)]
pub struct RevokeInput {
    pub signature_action: ActionHash,
    pub reason: Option<String>,
}

/// Input for sign_and_create — accepts everything except the signature,
/// which the conductor generates using the agent's key in the lair keystore.
#[derive(Serialize, Deserialize, Debug)]
pub struct SignAndCreateInput {
    pub file_hash: Vec<u8>,
    pub signed_at: i64,
    pub intent: Option<SigningIntent>,
    pub ai_generation: Option<AiGeneration>,
    pub content_rights: Option<ContentRights>,
    pub integrity_report: Option<IntegrityReport>,
    pub perceptual_hash: Option<PerceptualHash>,
    // v1.3 extensions
    pub supersedes: Option<ActionHash>,
    pub expires_at: Option<i64>,
    pub tags: Option<Vec<String>>,
    pub comment: Option<String>,
}

/// Input for set_thumbnail
#[derive(Serialize, Deserialize, Debug)]
pub struct SetThumbnailInput {
    pub signature_action: ActionHash,
    pub thumbnail: String,
}

// ── Create ──────────────────────────────────────────────────────────

/// Sign a file hash and create a SignatureRecord in one step.
/// The conductor signs the hash using the agent's key from the lair keystore.
/// No external signature needed — the zome handles both signing and committing.
#[hdk_extern]
pub fn sign_and_create(input: SignAndCreateInput) -> ExternResult<ActionHash> {
    if input.file_hash.len() != 32 {
        return Err(wasm_error!("file_hash must be exactly 32 bytes"));
    }

    // Sign the file hash using the conductor's lair keystore (agent's own key)
    let my_key = agent_info()?.agent_initial_pubkey;
    let sig = sign_raw(my_key.clone(), input.file_hash.clone())?;

    let record = SignatureRecord {
        file_hash: input.file_hash,
        signature: sig.0.to_vec(),
        signer: my_key,
        signed_at: input.signed_at,
        intent: input.intent,
        ai_generation: input.ai_generation,
        content_rights: input.content_rights,
        integrity_report: input.integrity_report,
        perceptual_hash: input.perceptual_hash,
        supersedes: input.supersedes,
        expires_at: input.expires_at,
        tags: input.tags,
        comment: input.comment,
    };

    create_signature(record)
}

/// Create a new SignatureRecord and add lookup links.
///
/// The caller must provide a valid Ed25519 signature over the file_hash.
/// Validation ensures: signer == author, signature verifies, file_hash is 32 bytes.
///
/// Creates links:
/// - FileHashToSignature: file_hash bytes -> ActionHash (exact verification lookup)
/// - AgentToSignature: AgentPubKey -> ActionHash (signing history)
/// - PerceptualBandToSignature: band bytes -> ActionHash (fuzzy matching, 4 bands if perceptual hash present)
#[hdk_extern]
pub fn create_signature(record: SignatureRecord) -> ExternResult<ActionHash> {
    // Commit the entry (validation runs automatically)
    let action_hash = create_entry(&EntryZomes::IntegritySigning(
        EntryTypes::SignatureRecord(record.clone()),
    ))?;

    // Link from file_hash for exact verification lookup
    let file_hash_linkable = ExternalHash::from_raw_36(hash_to_36_bytes(&record.file_hash));
    create_link(
        file_hash_linkable,
        action_hash.clone(),
        LinkTypes::FileHashToSignature,
        (),
    )?;

    // Link from agent for signing history
    let my_pub_key = agent_info()?.agent_initial_pubkey;
    create_link(
        my_pub_key,
        action_hash.clone(),
        LinkTypes::AgentToSignature,
        (),
    )?;

    // Create LSH band links for perceptual/fuzzy matching
    if let Some(ref phash) = record.perceptual_hash {
        for band in &phash.bands {
            let band_linkable = ExternalHash::from_raw_36(hash_to_36_bytes_padded(band));
            create_link(
                band_linkable,
                action_hash.clone(),
                LinkTypes::PerceptualBandToSignature,
                (),
            )?;
        }
    }

    Ok(action_hash)
}

// ── Read ────────────────────────────────────────────────────────────

/// Get all signatures for a given file hash.
/// Used by the verification page to look up who signed a file.
#[hdk_extern]
pub fn get_signatures_for_hash(file_hash: Vec<u8>) -> ExternResult<Vec<Record>> {
    if file_hash.len() != 32 {
        return Err(wasm_error!("file_hash must be exactly 32 bytes"));
    }

    let file_hash_linkable = ExternalHash::from_raw_36(hash_to_36_bytes(&file_hash));
    let links = get_links(
        LinkQuery::try_new(file_hash_linkable, LinkTypes::FileHashToSignature)?,
        GetStrategy::default(),
    )?;

    let mut records: Vec<Record> = Vec::new();
    for link in links {
        let action_hash = match ActionHash::try_from(link.target) {
            Ok(hash) => hash,
            Err(_) => continue,
        };

        if let Some(record) = get(action_hash, GetOptions::default())? {
            records.push(record);
        }
    }

    Ok(records)
}

/// Fuzzy lookup: find signatures with similar perceptual hashes.
/// Accepts the LSH bands from the query file's perceptual hash.
/// Queries each band and returns all candidate signatures (may include duplicates).
/// The caller should compute Hamming distance on the full hash to filter.
#[hdk_extern]
pub fn get_signatures_by_perceptual_bands(bands: Vec<Vec<u8>>) -> ExternResult<Vec<Record>> {
    let mut seen_hashes = std::collections::HashSet::new();
    let mut records: Vec<Record> = Vec::new();

    for band in bands {
        let band_linkable = ExternalHash::from_raw_36(hash_to_36_bytes_padded(&band));
        let links = get_links(
            LinkQuery::try_new(band_linkable, LinkTypes::PerceptualBandToSignature)?,
            GetStrategy::default(),
        )?;

        for link in links {
            let action_hash = match ActionHash::try_from(link.target) {
                Ok(hash) => hash,
                Err(_) => continue,
            };

            // Deduplicate — same signature may appear via multiple band matches
            let hash_bytes = action_hash.get_raw_39().to_vec();
            if !seen_hashes.insert(hash_bytes) {
                continue;
            }

            if let Some(record) = get(action_hash, GetOptions::default())? {
                records.push(record);
            }
        }
    }

    Ok(records)
}

/// Get all signatures created by a specific agent.
/// Used for cross-agent signature views (showing linked agents' signatures).
/// The signing DNA is public, so any agent can read another agent's signature links.
///
/// Accepts an AgentPubKey from any DNA context — reconstructs it with the correct
/// DHT location for this DNA using from_raw_32 (the last 4 bytes of a 39-byte
/// AgentPubKey encode a DNA-specific DHT location, so keys from other DNAs need
/// to be re-derived).
#[hdk_extern]
pub fn get_signatures_for_agent(agent: AgentPubKey) -> ExternResult<Vec<Record>> {
    // Re-derive the AgentPubKey for this DNA's DHT location.
    // Input may have DHT location bytes from a different DNA (e.g. identity DNA).
    let local_agent = AgentPubKey::from_raw_32(agent.get_raw_32().to_vec());
    let links = get_links(
        LinkQuery::try_new(local_agent, LinkTypes::AgentToSignature)?,
        GetStrategy::default(),
    )?;

    let mut records: Vec<Record> = Vec::new();
    for link in links {
        let action_hash = match ActionHash::try_from(link.target) {
            Ok(hash) => hash,
            Err(_) => continue,
        };

        if let Some(record) = get(action_hash, GetOptions::default())? {
            records.push(record);
        }
    }

    Ok(records)
}

/// Get all signatures created by the calling agent.
/// Used by the Vault signing history page.
#[hdk_extern]
pub fn get_my_signatures(_: ()) -> ExternResult<Vec<Record>> {
    let my_pub_key = agent_info()?.agent_initial_pubkey;
    let links = get_links(
        LinkQuery::try_new(my_pub_key, LinkTypes::AgentToSignature)?,
        GetStrategy::default(),
    )?;

    let mut records: Vec<Record> = Vec::new();
    for link in links {
        let action_hash = match ActionHash::try_from(link.target) {
            Ok(hash) => hash,
            Err(_) => continue,
        };

        if let Some(record) = get(action_hash, GetOptions::default())? {
            records.push(record);
        }
    }

    Ok(records)
}

// ── Revocation (Phase 2 — coordinator functions) ────────────────────

/// Revoke a signature by creating a RevocationEntry.
/// Only the original signer can revoke their own signature.
#[hdk_extern]
pub fn revoke_signature(input: RevokeInput) -> ExternResult<ActionHash> {
    let my_pub_key = agent_info()?.agent_initial_pubkey;

    // Get the original signature record to verify ownership
    let record = get(input.signature_action.clone(), GetOptions::default())?
        .ok_or(wasm_error!("Signature record not found"))?;

    let entry = record
        .entry()
        .as_option()
        .ok_or(wasm_error!("No entry data found"))?;

    let signature_record = SignatureRecord::try_from(entry)
        .map_err(|_| wasm_error!("Entry is not a SignatureRecord"))?;

    if my_pub_key != signature_record.signer {
        return Err(wasm_error!(
            "Only the original signer can revoke this signature"
        ));
    }

    let now = sys_time()?;
    let now_ms = now.as_seconds_and_nanos().0 * 1000
        + (now.as_seconds_and_nanos().1 as i64) / 1_000_000;

    let revocation = RevocationEntry {
        signature_action: input.signature_action.clone(),
        revoked_at: now_ms,
        reason: input.reason,
    };

    let revocation_hash = create_entry(&EntryZomes::IntegritySigning(
        EntryTypes::RevocationEntry(revocation),
    ))?;

    // Link from the original signature to the revocation for lookup
    create_link(
        input.signature_action,
        revocation_hash.clone(),
        LinkTypes::SignatureToRevocation,
        (),
    )?;

    Ok(revocation_hash)
}

/// Get all revocations for a given signature.
#[hdk_extern]
pub fn get_revocations_for_signature(signature_action: ActionHash) -> ExternResult<Vec<Record>> {
    let links = get_links(
        LinkQuery::try_new(signature_action, LinkTypes::SignatureToRevocation)?,
        GetStrategy::default(),
    )?;

    let mut records: Vec<Record> = Vec::new();
    for link in links {
        let action_hash = match ActionHash::try_from(link.target) {
            Ok(hash) => hash,
            Err(_) => continue,
        };

        if let Some(record) = get(action_hash, GetOptions::default())? {
            records.push(record);
        }
    }

    Ok(records)
}

// ── Export (for future migration) ───────────────────────────────────

/// Export all signature records created by the calling agent.
/// Used for data portability and DNA migration.
#[hdk_extern]
pub fn export_all_data(_: ()) -> ExternResult<Vec<SignatureRecord>> {
    let my_pub_key = agent_info()?.agent_initial_pubkey;
    let links = get_links(
        LinkQuery::try_new(my_pub_key, LinkTypes::AgentToSignature)?,
        GetStrategy::default(),
    )?;

    let mut signatures: Vec<SignatureRecord> = Vec::new();
    for link in links {
        let action_hash = match ActionHash::try_from(link.target) {
            Ok(hash) => hash,
            Err(_) => continue,
        };

        if let Some(record) = get(action_hash, GetOptions::default())? {
            if let Some(entry) = record.entry().as_option() {
                if let Ok(sig) = SignatureRecord::try_from(entry) {
                    signatures.push(sig);
                }
            }
        }
    }

    Ok(signatures)
}

// ── Thumbnails (v1.3) ──────────────────────────────────────────────

/// Set or update the thumbnail for a signature.
/// Only the original signer can set the thumbnail.
#[hdk_extern]
pub fn set_thumbnail(input: SetThumbnailInput) -> ExternResult<ActionHash> {
    let my_pub_key = agent_info()?.agent_initial_pubkey;

    // Verify the caller owns this signature
    let record = get(input.signature_action.clone(), GetOptions::default())?
        .ok_or(wasm_error!("Signature record not found"))?;
    let entry = record
        .entry()
        .as_option()
        .ok_or(wasm_error!("No entry data found"))?;
    let sig_record = SignatureRecord::try_from(entry)
        .map_err(|_| wasm_error!("Entry is not a SignatureRecord"))?;
    if my_pub_key != sig_record.signer {
        return Err(wasm_error!("Only the original signer can set the thumbnail"));
    }

    let now = sys_time()?;
    let now_ms = now.as_seconds_and_nanos().0 * 1000
        + (now.as_seconds_and_nanos().1 as i64) / 1_000_000;

    let thumbnail = SignatureThumbnail {
        signature_action: input.signature_action.clone(),
        thumbnail: input.thumbnail,
        updated_at: now_ms,
    };

    // Check if a thumbnail already exists (update it)
    let existing_links = get_links(
        LinkQuery::try_new(input.signature_action.clone(), LinkTypes::SignatureToThumbnail)?,
        GetStrategy::default(),
    )?;

    let thumbnail_hash = if let Some(link) = existing_links.first() {
        let existing_hash = ActionHash::try_from(link.target.clone())
            .map_err(|_| wasm_error!("Invalid thumbnail link target"))?;
        update_entry(
            existing_hash,
            &EntryZomes::IntegritySigning(EntryTypes::SignatureThumbnail(thumbnail)),
        )?
    } else {
        let hash = create_entry(&EntryZomes::IntegritySigning(
            EntryTypes::SignatureThumbnail(thumbnail),
        ))?;
        // Link from signature to thumbnail
        create_link(
            input.signature_action,
            hash.clone(),
            LinkTypes::SignatureToThumbnail,
            (),
        )?;
        hash
    };

    Ok(thumbnail_hash)
}

/// Get the thumbnail for a signature.
#[hdk_extern]
pub fn get_thumbnail(signature_action: ActionHash) -> ExternResult<Option<Record>> {
    let links = get_links(
        LinkQuery::try_new(signature_action, LinkTypes::SignatureToThumbnail)?,
        GetStrategy::default(),
    )?;

    if let Some(link) = links.first() {
        let hash = ActionHash::try_from(link.target.clone())
            .map_err(|_| wasm_error!("Invalid thumbnail link target"))?;

        // Follow update chain to get latest thumbnail
        let mut current_hash = hash;
        loop {
            let details = get_details(current_hash.clone(), GetOptions::default())?
                .ok_or(wasm_error!("Thumbnail not found"))?;
            match details {
                Details::Record(record_details) => {
                    if let Some(latest_update) = record_details.updates.last() {
                        current_hash = latest_update.action_address().clone();
                    } else {
                        return Ok(Some(record_details.record));
                    }
                }
                _ => return Ok(None),
            }
        }
    }

    Ok(None)
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Convert a 32-byte hash to a 36-byte ExternalHash representation.
/// ExternalHash uses: 3-byte prefix + 32-byte hash + 1-byte padding.
/// The prefix for ExternalHash is [0x84, 0x24, 0x24].
fn hash_to_36_bytes(hash: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(&[0x84, 0x24, 0x24]); // ExternalHash prefix
    bytes.extend_from_slice(hash);
    // Pad to 36 bytes if needed (32-byte hash + 3-byte prefix = 35, need 1 more)
    bytes.push(0x00);
    bytes
}

/// Convert a variable-length band to a 36-byte ExternalHash representation.
/// Pads shorter inputs with zeros to fill the 32-byte hash portion.
fn hash_to_36_bytes_padded(data: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(&[0x84, 0x24, 0x24]); // ExternalHash prefix
    bytes.extend_from_slice(&data[..data.len().min(32)]);
    // Pad to 36 total bytes
    while bytes.len() < 36 {
        bytes.push(0x00);
    }
    bytes
}
