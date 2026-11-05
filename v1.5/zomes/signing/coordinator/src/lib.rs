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
        carried_from: None,
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
    if record.carried_from.is_some() {
        return Err(wasm_error!("carried records are created through carry_signature"));
    }
    commit_signature(record)
}

/// Commit a SignatureRecord (native or carried) and its lookup links. The
/// signing-history link is from the record's signer: for a carried record
/// that is the original author, so their history finds it on this network.
fn commit_signature(record: SignatureRecord) -> ExternResult<ActionHash> {
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

    // Link from the signer for signing history (re-derived for this DNA's
    // DHT location, as get_signatures_for_agent does for lookups)
    let signer_here = AgentPubKey::from_raw_32(record.signer.get_raw_32().to_vec());
    create_link(
        signer_here,
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
    let records = kept_targets(file_hash_linkable, LinkTypes::FileHashToSignature, GetStrategy::default(), GetOptions::default())?;
    // Only signatures of this file.
    Ok(records
        .into_iter()
        .filter(|r| signature_of(r).is_some_and(|s| s.file_hash == file_hash))
        .collect())
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
        for record in kept_targets(band_linkable, LinkTypes::PerceptualBandToSignature, GetStrategy::default(), GetOptions::default())? {
            // Deduplicate — same signature may appear via multiple band matches
            if signature_of(&record).is_none() || !seen_hashes.insert(record.action_address().get_raw_39().to_vec()) {
                continue;
            }
            records.push(record);
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
    signed_by(local_agent, GetStrategy::default(), GetOptions::default())
}

/// Get all signatures created by the calling agent.
/// Used by the Vault signing history page.
#[hdk_extern]
pub fn get_my_signatures(_: ()) -> ExternResult<Vec<Record>> {
    // Own-agent links and records are always self-authored: read them from
    // the local databases only. A network lookup here can hang for minutes
    // on a cold conductor and never returns anything the chain doesn't
    // already hold.
    let my_pub_key = agent_info()?.agent_initial_pubkey;
    signed_by(my_pub_key, GetStrategy::Local, GetOptions::local())
}

/// Get signatures created by the calling agent since a given timestamp.
/// Used by the API to poll for new signatures that arrived via gossip
/// (e.g. signed in Vault, gossipped to server) for webhook delivery.
/// Returns signatures with signed_at >= since_ms.
#[hdk_extern]
pub fn get_my_signatures_since(since_ms: i64) -> ExternResult<Vec<Record>> {
    // Same self-authored rule as get_my_signatures; records that arrive by
    // gossip are integrated into the local database before they are
    // queryable either way.
    let my_pub_key = agent_info()?.agent_initial_pubkey;
    Ok(signed_by(my_pub_key, GetStrategy::Local, GetOptions::local())?
        .into_iter()
        .filter(|r| signature_of(r).is_some_and(|s| s.signed_at >= since_ms))
        .collect())
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
        carried_from: None,
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

/// Get all revocations for a given signature (see `revocations_by_signer`).
#[hdk_extern]
pub fn get_revocations_for_signature(signature_action: ActionHash) -> ExternResult<Vec<Record>> {
    revocations_by_signer(signature_action, GetStrategy::default(), GetOptions::default())
}

/// LOCAL variant for the signer's own view: a signature's revocation can
/// only ever be authored by its signer, so for own records the local
/// database is complete — no network round-trip. The network variant
/// above stays for cross-agent verification surfaces.
#[hdk_extern]
pub fn get_own_revocations_for_signature(
    signature_action: ActionHash,
) -> ExternResult<Vec<Record>> {
    revocations_by_signer(signature_action, GetStrategy::Local, GetOptions::local())
}

// ── Carried records (v1.5: the move from v1.4) ──────────────────────

/// Input for carry_signature: the record as it was on the previous network
/// (`carried_from` must be `None`; it is filled here with this agent as the
/// witness) plus where it came from.
#[derive(Serialize, Deserialize, Debug)]
pub struct CarrySignatureInput {
    pub record: SignatureRecord,
    pub original_action_hash: ActionHash,
    pub original_timestamp: i64,
    pub original_signed_action: Option<Vec<u8>>,
}

/// Input for carry_revocation / carry_thumbnail: the record's fields with
/// `signature_action` already mapped to the signature's hash on THIS
/// network (use `get_carried` on the old signature hash first).
#[derive(Serialize, Deserialize, Debug)]
pub struct CarryRevocationInput {
    pub signature_action: ActionHash,
    pub revoked_at: i64,
    pub reason: Option<String>,
    pub original_author: AgentPubKey,
    pub original_action_hash: ActionHash,
    pub original_timestamp: i64,
    pub original_signed_action: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CarryThumbnailInput {
    pub signature_action: ActionHash,
    pub thumbnail: String,
    pub updated_at: i64,
    pub original_author: AgentPubKey,
    pub original_action_hash: ActionHash,
    pub original_timestamp: i64,
    pub original_signed_action: Vec<u8>,
}

/// The record's ActionHash on this network for an action hash on the
/// previous one, when THIS agent carried it; `None` otherwise.
///
/// Coordinator rev 2: a LOCAL read. The index link is written by the
/// witness, and the only question the carries ask is "did I carry this
/// already" - a network lookup here waited the full request timeout on a
/// conductor with no warm peers (240 s per record, Vault 1.7.0 live test,
/// 2026-10-26), the same hang the v1.4 self-authored lookups had.
///
/// Coordinator rev 3: this agent's own index links.
#[hdk_extern]
pub fn get_carried(original_action_hash: ActionHash) -> ExternResult<Option<ActionHash>> {
    let me = agent_info()?.agent_initial_pubkey;
    let details = get_links_details(
        LinkQuery::try_new(carried_base(&original_action_hash), LinkTypes::CarriedIndex)?,
        GetStrategy::Local,
    )?;
    for (create, removals) in details.into_inner() {
        if *create.action().author() != me || removals.iter().any(|r| *r.action().author() == me) {
            continue;
        }
        if let ActionData::CreateLink(link) = &create.action().data {
            if let Ok(hash) = ActionHash::try_from(link.target_address.clone()) {
                return Ok(Some(hash));
            }
        }
    }
    Ok(None)
}

fn index_carried(original_action_hash: &ActionHash, new_action_hash: &ActionHash) -> ExternResult<()> {
    create_link(
        carried_base(original_action_hash),
        new_action_hash.clone(),
        LinkTypes::CarriedIndex,
        (),
    )?;
    Ok(())
}

/// Carry a signature from the previous network. The calling agent is the
/// witness; the record's signer stays the original author and its embedded
/// Ed25519 signature is what validation checks. Idempotent by the old
/// action hash: a second carry returns the hash of the first.
#[hdk_extern]
pub fn carry_signature(input: CarrySignatureInput) -> ExternResult<ActionHash> {
    if let Some(existing) = get_carried(input.original_action_hash.clone())? {
        return Ok(existing);
    }
    if input.record.carried_from.is_some() {
        return Err(wasm_error!("the record's carried_from is set here, not by the caller"));
    }
    let witness = agent_info()?.agent_initial_pubkey;
    let mut record = input.record;
    record.carried_from = Some(CarriedFrom {
        original_author: record.signer.clone(),
        original_timestamp: input.original_timestamp,
        original_action_hash: input.original_action_hash.clone(),
        original_signed_action: input.original_signed_action,
        witness,
        certificate: None,
    });
    let hash = commit_signature(record)?;
    index_carried(&input.original_action_hash, &hash)?;
    Ok(hash)
}

/// Carry a revocation: its proof is the original signed action.
#[hdk_extern]
pub fn carry_revocation(input: CarryRevocationInput) -> ExternResult<ActionHash> {
    if let Some(existing) = get_carried(input.original_action_hash.clone())? {
        return Ok(existing);
    }
    let witness = agent_info()?.agent_initial_pubkey;
    let revocation = RevocationEntry {
        signature_action: input.signature_action.clone(),
        revoked_at: input.revoked_at,
        reason: input.reason,
        carried_from: Some(CarriedFrom {
            original_author: input.original_author,
            original_timestamp: input.original_timestamp,
            original_action_hash: input.original_action_hash.clone(),
            original_signed_action: Some(input.original_signed_action),
            witness,
            certificate: None,
        }),
    };
    let hash = create_entry(&EntryZomes::IntegritySigning(EntryTypes::RevocationEntry(revocation)))?;
    create_link(input.signature_action, hash.clone(), LinkTypes::SignatureToRevocation, ())?;
    index_carried(&input.original_action_hash, &hash)?;
    Ok(hash)
}

/// Carry a thumbnail (the latest one the previous network held).
#[hdk_extern]
pub fn carry_thumbnail(input: CarryThumbnailInput) -> ExternResult<ActionHash> {
    if let Some(existing) = get_carried(input.original_action_hash.clone())? {
        return Ok(existing);
    }
    let witness = agent_info()?.agent_initial_pubkey;
    let thumbnail = SignatureThumbnail {
        signature_action: input.signature_action.clone(),
        thumbnail: input.thumbnail,
        updated_at: input.updated_at,
        carried_from: Some(CarriedFrom {
            original_author: input.original_author,
            original_timestamp: input.original_timestamp,
            original_action_hash: input.original_action_hash.clone(),
            original_signed_action: Some(input.original_signed_action),
            witness,
            certificate: None,
        }),
    };
    let hash = create_entry(&EntryZomes::IntegritySigning(EntryTypes::SignatureThumbnail(thumbnail)))?;
    create_link(input.signature_action, hash.clone(), LinkTypes::SignatureToThumbnail, ())?;
    index_carried(&input.original_action_hash, &hash)?;
    Ok(hash)
}

// ── Export (for future migration) ───────────────────────────────────

/// Export all signature records created by the calling agent.
/// Used for data portability and DNA migration.
#[hdk_extern]
pub fn export_all_data(_: ()) -> ExternResult<Vec<SignatureRecord>> {
    let my_pub_key = agent_info()?.agent_initial_pubkey;
    Ok(signed_by(my_pub_key, GetStrategy::default(), GetOptions::default())?
        .iter()
        .filter_map(signature_of)
        .collect())
}

// ── Thumbnails ─────────────────────────────────────────────────────

/// Set or update the thumbnail for a signature.
/// No ownership check — the agent is authenticated via lair (only the cell
/// owner can create entries). The signature may live on a different conductor
/// (e.g. Website signature edited from Vault), so `get(action_hash)` would
/// fail for cross-conductor action hashes.
#[hdk_extern]
pub fn set_thumbnail(input: SetThumbnailInput) -> ExternResult<ActionHash> {
    let now = sys_time()?;
    let now_ms = now.as_seconds_and_nanos().0 * 1000
        + (now.as_seconds_and_nanos().1 as i64) / 1_000_000;

    let thumbnail = SignatureThumbnail {
        signature_action: input.signature_action.clone(),
        thumbnail: input.thumbnail,
        updated_at: now_ms,
        carried_from: None,
    };

    // Check if a thumbnail already exists (update it). Thumbnail links on
    // own signatures are self-authored — a LOCAL read is complete, and a
    // network read here hung for minutes on cold conductors.
    // Update a thumbnail this agent wrote (readers follow its author's
    // updates).
    let my_pub_key = agent_info()?.agent_initial_pubkey;
    let mine = kept_targets(input.signature_action.clone(), LinkTypes::SignatureToThumbnail, GetStrategy::Local, GetOptions::local())?
        .into_iter()
        .find(|r| *r.action().author() == my_pub_key);

    let thumbnail_hash = if let Some(existing) = mine {
        update_entry(
            existing.action_address().clone(),
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
    // Thumbnails are written by the signature's owner; for own records the
    // local database is complete. For linked-agent history a remote-authored
    // thumbnail becomes visible once gossip integrates it — additive
    // catch-up, same as the rest of the linked view.
    // The signer's own thumbnail when there is one.
    let thumbnails = kept_targets(signature_action.clone(), LinkTypes::SignatureToThumbnail, GetStrategy::Local, GetOptions::local())?;
    let signer = kept_record(signature_action, GetOptions::local())?
        .as_ref()
        .and_then(signature_of)
        .map(|s| s.signer.get_raw_32().to_vec());
    let by_signer = thumbnails.iter().find(|t| signer.as_deref() == Some(t.action().author().get_raw_32()));
    let Some(first) = by_signer.or(thumbnails.first()).cloned() else {
        return Ok(None);
    };

    // Follow the update chain to the latest thumbnail, by its author's own
    // updates.
    let author = first.action().author().clone();
    let mut current_hash = first.action_address().clone();
    loop {
        match get_details(current_hash.clone(), GetOptions::local())? {
            Some(Details::Record(record_details)) => {
                match record_details.updates.iter().rev().find(|u| *u.action().author() == author) {
                    Some(update) => current_hash = update.action_address().clone(),
                    None => return Ok(Some(record_details.record)),
                }
            }
            _ => return Ok(None),
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

// Readers go by the details: a record or link counts as deleted or removed
// when its own author did so, and each record found must be what its
// lookup says it is.

/// A record, unless its own author deleted it.
fn kept_record(hash: ActionHash, options: GetOptions) -> ExternResult<Option<Record>> {
    match get_details(hash, options)? {
        Some(Details::Record(details)) => {
            let author = details.record.action().author().clone();
            let deleted = details.deletes.iter().any(|d| *d.action().author() == author);
            Ok((!deleted).then_some(details.record))
        }
        _ => Ok(None),
    }
}

/// The records `base`'s links of `link_type` point at, skipping a link its
/// own author removed and a record its own author deleted.
fn kept_targets(
    base: impl Into<AnyLinkableHash>,
    link_type: LinkTypes,
    strategy: GetStrategy,
    options: GetOptions,
) -> ExternResult<Vec<Record>> {
    let mut records = Vec::new();
    for (create, removals) in get_links_details(LinkQuery::try_new(base, link_type)?, strategy)?.into_inner() {
        let author = create.action().author();
        if removals.iter().any(|r| r.action().author() == author) {
            continue;
        }
        let ActionData::CreateLink(link) = &create.action().data else { continue };
        let Ok(hash) = ActionHash::try_from(link.target_address.clone()) else { continue };
        if let Some(record) = kept_record(hash, options.clone())? {
            records.push(record);
        }
    }
    Ok(records)
}

fn signature_of(record: &Record) -> Option<SignatureRecord> {
    record.entry().as_option().and_then(|e| SignatureRecord::try_from(e).ok())
}

/// `agent`'s signatures: the records its signing-history links point at
/// whose signer is `agent`.
fn signed_by(agent: AgentPubKey, strategy: GetStrategy, options: GetOptions) -> ExternResult<Vec<Record>> {
    let raw = agent.get_raw_32().to_vec();
    Ok(kept_targets(agent, LinkTypes::AgentToSignature, strategy, options)?
        .into_iter()
        .filter(|r| signature_of(r).is_some_and(|s| s.signer.get_raw_32() == raw.as_slice()))
        .collect())
}

/// A signature's revocations: those written by its signer, or by whoever
/// wrote this copy of it (a carried copy's witness, whose own carry of the
/// revocation travels with it).
fn revocations_by_signer(signature_action: ActionHash, strategy: GetStrategy, options: GetOptions) -> ExternResult<Vec<Record>> {
    let Some(signature) = kept_record(signature_action.clone(), options.clone())? else {
        return Ok(Vec::new());
    };
    let Some(signer) = signature_of(&signature).map(|s| s.signer) else {
        return Ok(Vec::new());
    };
    let may_revoke = [signer.get_raw_32().to_vec(), signature.action().author().get_raw_32().to_vec()];
    Ok(kept_targets(signature_action.clone(), LinkTypes::SignatureToRevocation, strategy, options)?
        .into_iter()
        .filter(|r| {
            let names_it = r
                .entry()
                .as_option()
                .and_then(|e| RevocationEntry::try_from(e).ok())
                .is_some_and(|rev| rev.signature_action == signature_action);
            names_it && may_revoke.iter().any(|k| k.as_slice() == r.action().author().get_raw_32())
        })
        .collect())
}

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
