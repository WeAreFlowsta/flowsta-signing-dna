//! Flowsta Signing DNA v1.5 on a real Holochain 0.7.1 conductor.
//!
//! Loads the packed bundle from `../workdir/flowsta_signing_v1_5.dna` (the
//! bytes that ship), so a passing run says the committed artifact works on
//! this conductor: every validation arm, a signature carried from one agent
//! to another with its embedded proof intact, and two conductors gossiping.

use holochain::prelude::*;
use holochain::sweettest::*;
use signing_coordinator::{
    CarryRevocationInput, CarrySignatureInput, RevokeInput, SetThumbnailInput, SignAndCreateInput,
};
use signing_integrity::{RevocationEntry, SignatureRecord};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const ZOME: &str = "signing";

async fn dna() -> DnaFile {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../workdir/flowsta_signing_v1_5.dna");
    SweetDnaFile::from_bundle(&path)
        .await
        .expect("v1.5/workdir/flowsta_signing_v1_5.dna loads (run build.sh first)")
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn sign_input(hash_byte: u8) -> SignAndCreateInput {
    SignAndCreateInput {
        file_hash: vec![hash_byte; 32],
        signed_at: now_ms(),
        intent: None,
        ai_generation: None,
        content_rights: None,
        integrity_report: None,
        perceptual_hash: None,
        supersedes: None,
        expires_at: None,
        tags: Some(vec!["test".to_string()]),
        comment: Some("sweettest".to_string()),
    }
}

fn decode<T: TryFrom<SerializedBytes, Error = SerializedBytesError>>(record: &Record) -> T {
    record
        .entry()
        .to_app_option::<T>()
        .ok()
        .flatten()
        .expect("record carries the expected app entry")
}

/// Every arm of `validate`, reached through the coordinator the apps use.
#[tokio::test(flavor = "multi_thread")]
async fn validation_arms() {
    let mut conductor = SweetConductor::standard().await;
    let app = conductor.setup_app("signing", [&dna().await]).await.unwrap();
    let zome = app.cells()[0].zome(ZOME);

    // Native signature: the conductor signs with the agent's lair key.
    let sig_hash: ActionHash = conductor.call(&zome, "sign_and_create", sign_input(1)).await;
    let found: Vec<Record> = conductor.call(&zome, "get_signatures_for_hash", vec![1u8; 32]).await;
    assert_eq!(found.len(), 1);
    let rec: SignatureRecord = decode(&found[0]);
    assert_eq!(&rec.signer, app.agent());
    assert!(rec.carried_from.is_none());
    assert_eq!(rec.signature.len(), 64);

    // Wrong hash length is refused before signing.
    let short: Result<ActionHash, _> = conductor
        .call_fallible(&zome, "sign_and_create", SignAndCreateInput { file_hash: vec![1u8; 31], ..sign_input(1) })
        .await;
    assert!(short.is_err());

    // A record claiming another signer fails validation (signer must be the author).
    let forged = SignatureRecord { signer: AgentPubKey::from_raw_32(vec![7u8; 32]), ..rec.clone() };
    let r: Result<ActionHash, _> = conductor.call_fallible(&zome, "create_signature", forged).await;
    assert!(r.is_err(), "a native record must be signed by its author");

    // A record whose embedded signature does not match fails validation.
    let mut bad_sig = rec.clone();
    bad_sig.signature[0] ^= 0xff;
    let r: Result<ActionHash, _> = conductor.call_fallible(&zome, "create_signature", bad_sig).await;
    assert!(r.is_err(), "the embedded Ed25519 signature is checked");

    // Too many tags.
    let r: Result<ActionHash, _> = conductor
        .call_fallible(&zome, "sign_and_create", SignAndCreateInput { tags: Some((0..6).map(|i| i.to_string()).collect()), ..sign_input(2) })
        .await;
    assert!(r.is_err());

    // Own history, local read.
    let mine: Vec<Record> = conductor.call(&zome, "get_my_signatures", ()).await;
    assert_eq!(mine.len(), 1);

    // Thumbnail: set, update, read the latest.
    let _: ActionHash = conductor
        .call(&zome, "set_thumbnail", SetThumbnailInput { signature_action: sig_hash.clone(), thumbnail: "data:image/jpeg;base64,AAA".into() })
        .await;
    let _: ActionHash = conductor
        .call(&zome, "set_thumbnail", SetThumbnailInput { signature_action: sig_hash.clone(), thumbnail: "data:image/jpeg;base64,BBB".into() })
        .await;
    let latest: Option<Record> = conductor.call(&zome, "get_thumbnail", sig_hash.clone()).await;
    let t: signing_integrity::SignatureThumbnail = decode(&latest.expect("a thumbnail"));
    assert!(t.thumbnail.ends_with("BBB"));
    let r: Result<ActionHash, _> = conductor
        .call_fallible(&zome, "set_thumbnail", SetThumbnailInput { signature_action: sig_hash.clone(), thumbnail: "not a data uri".into() })
        .await;
    assert!(r.is_err());

    // Revocation by the signer; a 300-char reason is refused.
    let r: Result<ActionHash, _> = conductor
        .call_fallible(&zome, "revoke_signature", RevokeInput { signature_action: sig_hash.clone(), reason: Some("x".repeat(300)) })
        .await;
    assert!(r.is_err());
    let _: ActionHash = conductor
        .call(&zome, "revoke_signature", RevokeInput { signature_action: sig_hash.clone(), reason: Some("superseded".into()) })
        .await;
    let revs: Vec<Record> = conductor.call(&zome, "get_own_revocations_for_signature", sig_hash.clone()).await;
    assert_eq!(revs.len(), 1);
    let rv: RevocationEntry = decode(&revs[0]);
    assert!(rv.carried_from.is_none());
}

/// A signature authored by alice is carried onto this network by bob as the
/// witness: the signer stays alice, the embedded signature still verifies,
/// alice's history finds it, the old hash maps to the new one, and a second
/// carry is a no-op. A carried revocation follows; one without its original
/// signed action is refused.
#[tokio::test(flavor = "multi_thread")]
async fn carried_records() {
    let dna = dna().await;
    let mut conductors = SweetConductorBatch::standard(2).await;
    let apps = conductors.setup_app("signing", [&dna]).await.unwrap();
    conductors.exchange_peer_info().await;
    let ((alice,), (bob,)) = apps.into_tuples();
    let alice_zome = alice.zome(ZOME);
    let bob_zome = bob.zome(ZOME);
    let a = conductors.get(0).unwrap();
    let b = conductors.get(1).unwrap();

    // Alice signs natively (this stands in for her v1.4 record).
    let alice_hash: ActionHash = a.call(&alice_zome, "sign_and_create", sign_input(9)).await;
    let alice_records: Vec<Record> = a.call(&alice_zome, "get_my_signatures", ()).await;
    let alice_record = alice_records.iter().find(|r| r.action_address() == &alice_hash).unwrap().clone();
    let entry: SignatureRecord = decode(&alice_record);
    let signed_action_bytes = holochain_serialized_bytes::encode(alice_record.signed_action()).unwrap();
    let original_ts = alice_record.action().timestamp().as_millis();

    // Bob carries it, pretending the old network is gone: a different hash
    // stands in for her v1.4 action hash.
    let old_hash = ActionHash::from_raw_32(vec![0xAB; 32]);
    let carried: ActionHash = b
        .call(
            &bob_zome,
            "carry_signature",
            CarrySignatureInput {
                record: entry.clone(),
                original_action_hash: old_hash.clone(),
                original_timestamp: original_ts,
                original_signed_action: Some(signed_action_bytes.clone()),
            },
        )
        .await;
    assert_ne!(carried, alice_hash);

    // Idempotent by the old hash.
    let again: ActionHash = b
        .call(
            &bob_zome,
            "carry_signature",
            CarrySignatureInput { record: entry.clone(), original_action_hash: old_hash.clone(), original_timestamp: original_ts, original_signed_action: None },
        )
        .await;
    assert_eq!(again, carried);
    let mapped: Option<ActionHash> = b.call(&bob_zome, "get_carried", old_hash.clone()).await;
    assert_eq!(mapped, Some(carried.clone()));

    // What bob's network holds: the carried record, signer alice, witness bob.
    let by_hash: Vec<Record> = b.call(&bob_zome, "get_signatures_for_hash", vec![9u8; 32]).await;
    let carried_rec = by_hash.iter().find(|r| r.action_address() == &carried).expect("carried record found by file hash");
    assert_eq!(carried_rec.action().author(), bob.agent_pubkey());
    let ce: SignatureRecord = decode(carried_rec);
    assert_eq!(&ce.signer, alice.agent_pubkey());
    let from = ce.carried_from.expect("carried_from set by the zome");
    assert_eq!(&from.witness, bob.agent_pubkey());
    assert_eq!(&from.original_author, alice.agent_pubkey());
    assert_eq!(from.original_action_hash, old_hash);
    assert_eq!(from.original_signed_action, Some(signed_action_bytes.clone()));

    // Alice's history on this network includes the carried record (linked from her key).
    let alice_history: Vec<Record> = b.call(&bob_zome, "get_signatures_for_agent", alice.agent_pubkey().clone()).await;
    assert!(alice_history.iter().any(|r| r.action_address() == &carried));

    // A carried record with a tampered embedded signature is refused.
    let mut tampered = entry.clone();
    tampered.signature[1] ^= 0xff;
    let r: Result<ActionHash, _> = b
        .call_fallible(
            &bob_zome,
            "carry_signature",
            CarrySignatureInput { record: tampered, original_action_hash: ActionHash::from_raw_32(vec![0xAC; 32]), original_timestamp: original_ts, original_signed_action: None },
        )
        .await;
    assert!(r.is_err(), "a carried signature still has to verify against its signer");

    // A carried revocation needs its original signed action.
    let r: Result<ActionHash, _> = b
        .call_fallible(
            &bob_zome,
            "carry_revocation",
            CarryRevocationInput {
                signature_action: carried.clone(),
                revoked_at: original_ts + 1,
                reason: None,
                original_author: alice.agent_pubkey().clone(),
                original_action_hash: ActionHash::from_raw_32(vec![0xAD; 32]),
                original_timestamp: original_ts + 1,
                original_signed_action: vec![],
            },
        )
        .await;
    assert!(r.is_err(), "an empty signed action is refused");
    let rev: ActionHash = b
        .call(
            &bob_zome,
            "carry_revocation",
            CarryRevocationInput {
                signature_action: carried.clone(),
                revoked_at: original_ts + 1,
                reason: Some("carried".into()),
                original_author: alice.agent_pubkey().clone(),
                original_action_hash: ActionHash::from_raw_32(vec![0xAD; 32]),
                original_timestamp: original_ts + 1,
                original_signed_action: signed_action_bytes.clone(),
            },
        )
        .await;
    let revs: Vec<Record> = b.call(&bob_zome, "get_revocations_for_signature", carried.clone()).await;
    assert_eq!(revs.iter().filter(|r| r.action_address() == &rev).count(), 1);

    // Gossip: alice's conductor sees bob's carried copy by file hash.
    await_consistency([&alice, &bob]).await.expect("carried records reach alice");
    let on_alice: Vec<Record> = a.call(&alice_zome, "get_signatures_for_hash", vec![9u8; 32]).await;
    assert!(on_alice.iter().any(|r| r.action_address() == &carried));
    assert!(on_alice.iter().any(|r| r.action_address() == &alice_hash));
}
