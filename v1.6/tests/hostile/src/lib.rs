//! Test only. What a stranger can write against the signing integrity zome
//! with a coordinator of their own: the network checks no author on a
//! delete, an update or a link removal, and none on who revokes. The
//! sweettests run this beside the real coordinator to check that readers
//! are not fooled by any of it.

use hdk::prelude::*;
use signing_integrity::*;

#[hdk_dependent_entry_types]
enum EntryZomes {
    IntegritySigning(signing_integrity::EntryTypes),
}

fn now_ms() -> ExternResult<i64> {
    Ok(sys_time()?.as_millis())
}

/// The coordinator's file-hash base (`hash_to_36_bytes`).
fn file_base(file_hash: &[u8]) -> ExternalHash {
    let mut bytes = vec![0x84, 0x24, 0x24];
    bytes.extend_from_slice(file_hash);
    bytes.push(0x00);
    ExternalHash::from_raw_36(bytes)
}

fn remove_all(base: AnyLinkableHash, link_type: LinkTypes) -> ExternResult<u32> {
    let links = get_links(LinkQuery::try_new(base, link_type)?, GetStrategy::Network)?;
    for link in &links {
        delete_link(link.create_link_hash.clone(), GetOptions::default())?;
    }
    Ok(links.len() as u32)
}

/// A revocation of someone else's signature.
#[hdk_extern]
pub fn forge_revocation(signature_action: ActionHash) -> ExternResult<ActionHash> {
    let revocation = RevocationEntry { signature_action: signature_action.clone(), revoked_at: now_ms()?, reason: Some("forged".into()), carried_from: None };
    let hash = create_entry(&EntryZomes::IntegritySigning(EntryTypes::RevocationEntry(revocation)))?;
    create_link(signature_action, hash.clone(), LinkTypes::SignatureToRevocation, ())?;
    Ok(hash)
}

/// Delete someone else's record.
#[hdk_extern]
pub fn delete_record(hash: ActionHash) -> ExternResult<ActionHash> {
    delete_entry(hash)
}

#[hdk_extern]
pub fn remove_file_links(file_hash: Vec<u8>) -> ExternResult<u32> {
    remove_all(file_base(&file_hash).into(), LinkTypes::FileHashToSignature)
}

#[hdk_extern]
pub fn remove_agent_links(agent: AgentPubKey) -> ExternResult<u32> {
    remove_all(agent.into(), LinkTypes::AgentToSignature)
}

#[hdk_extern]
pub fn remove_revocation_links(signature_action: ActionHash) -> ExternResult<u32> {
    remove_all(signature_action.into(), LinkTypes::SignatureToRevocation)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileLinkInput {
    pub file_hash: Vec<u8>,
    pub signature_action: ActionHash,
}

/// File someone's signature under another file's hash.
#[hdk_extern]
pub fn link_file(input: FileLinkInput) -> ExternResult<ActionHash> {
    create_link(file_base(&input.file_hash), input.signature_action, LinkTypes::FileHashToSignature, ())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AgentLinkInput {
    pub agent: AgentPubKey,
    pub signature_action: ActionHash,
}

/// File a signature under someone else's signing history.
#[hdk_extern]
pub fn link_agent(input: AgentLinkInput) -> ExternResult<ActionHash> {
    create_link(input.agent, input.signature_action, LinkTypes::AgentToSignature, ())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ThumbnailUpdateInput {
    pub thumbnail_action: ActionHash,
    pub signature_action: ActionHash,
}

/// Replace someone else's thumbnail by updating it.
#[hdk_extern]
pub fn update_thumbnail(input: ThumbnailUpdateInput) -> ExternResult<ActionHash> {
    let thumbnail = SignatureThumbnail { signature_action: input.signature_action, thumbnail: "data:image/png;base64,Zm9yZ2Vk".into(), updated_at: now_ms()?, carried_from: None };
    update_entry(input.thumbnail_action, &EntryZomes::IntegritySigning(EntryTypes::SignatureThumbnail(thumbnail)))
}
