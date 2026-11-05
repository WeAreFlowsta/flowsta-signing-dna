//! Flowsta Signing DNA v1.6 on a real Holochain 0.7.1 conductor.
//!
//! Loads the packed bundle from `../workdir/flowsta_signing_v1_6.dna` (the
//! bytes that ship) with this repo's coordinator applied over it, as the
//! apps apply it, so a passing run says what ships works on this conductor:
//! every validation arm, records carried from v1.5 (real ones, written on
//! the shipped v1.5 bundle beside it) and from v1.4 (the 0.6 action shape)
//! with their proofs checked, each forged proof refused, and two conductors
//! gossiping.

use holochain::prelude::*;
use holochain::sweettest::*;
use signing_coordinator::{
    CarryRevocationInput, CarrySignatureInput, CarryThumbnailInput, Original, RevokeInput, SetThumbnailInput,
    SignAndCreateInput,
};
use signing_integrity::{RevocationEntry, SignatureRecord};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const ZOME: &str = "signing";

async fn dna() -> DnaFile {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../workdir/flowsta_signing_v1_6.dna");
    SweetDnaFile::from_bundle(&path)
        .await
        .expect("v1.6/workdir/flowsta_signing_v1_6.dna loads (run build.sh first)")
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
    let app = conductor.setup_app("signing", [&shipped_coordinator().await]).await.unwrap();
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

/// The shipped v1.5 bundle, for records to carry from.
async fn dna_v15() -> DnaFile {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../v1.5/workdir/flowsta_signing_v1_5.dna");
    SweetDnaFile::from_bundle(&path).await.expect("v1.5/workdir/flowsta_signing_v1_5.dna loads")
}

/// A v1.5 record's original, exactly as its author signed it: the action as
/// 0.7 encodes it, the signature, the entry's bytes.
fn original_v15(record: &Record) -> Original {
    let Some(Entry::App(bytes)) = record.entry().as_option() else { panic!("an app entry") };
    Original {
        dna: "1.5".into(),
        action_hash: record.action_address().clone(),
        author: record.action().author().clone(),
        timestamp: record.action().timestamp(),
        action: holochain_serialized_bytes::encode(record.action()).unwrap(),
        signature: record.signature().clone(),
        entry: bytes.bytes().to_vec(),
    }
}

/// The fields of a v1.4 SignatureRecord (no `carried_from`), as 0.6 wrote it.
#[derive(serde::Serialize, Debug)]
struct SignatureV14 {
    file_hash: Vec<u8>,
    signature: Vec<u8>,
    signer: AgentPubKey,
    signed_at: i64,
    intent: Option<signing_integrity::SigningIntent>,
    ai_generation: Option<signing_integrity::AiGeneration>,
    content_rights: Option<signing_integrity::ContentRights>,
    integrity_report: Option<signing_integrity::IntegrityReport>,
    perceptual_hash: Option<signing_integrity::PerceptualHash>,
    supersedes: Option<ActionHash>,
    expires_at: Option<i64>,
    tags: Option<Vec<String>>,
    comment: Option<String>,
}

#[derive(serde::Serialize, Debug)]
struct RevocationV14 {
    signature_action: ActionHash,
    revoked_at: i64,
    reason: Option<String>,
}

/// A Holochain 0.6 Create as it encodes (an enum tagged by `type`).
#[derive(serde::Serialize, Debug)]
#[serde(tag = "type")]
enum Action06 {
    Create(Create06),
}

#[derive(serde::Serialize, Debug)]
struct Create06 {
    author: AgentPubKey,
    timestamp: Timestamp,
    action_seq: u32,
    prev_action: ActionHash,
    entry_type: EntryType,
    entry_hash: EntryHash,
}

/// A v1.4-shaped original: `entry` written by `author` as entry `entry_index`
/// of the signing zome, the action signed by `author`'s key on `conductor`.
async fn original_v14(conductor: &SweetConductor, author: &AgentPubKey, entry_index: u8, entry: Vec<u8>, at: Timestamp) -> Original {
    let entry_hash = EntryHash::with_data_sync(&Entry::App(AppEntryBytes(SerializedBytes::from(UnsafeBytes::from(entry.clone())))));
    let action = Action06::Create(Create06 {
        author: author.clone(),
        timestamp: at,
        action_seq: 7,
        prev_action: ActionHash::from_raw_32(vec![0x11; 32]),
        entry_type: EntryType::App(AppEntryDef::new(entry_index.into(), 0.into(), EntryVisibility::Public)),
        entry_hash,
    });
    let bytes = holochain_serialized_bytes::encode(&action).unwrap();
    let signature = conductor.keystore().sign(author.clone(), bytes.clone().into()).await.unwrap();
    Original {
        dna: "1.4".into(),
        action_hash: ActionHash::from_raw_32(holo_hash::encode::blake2b_256(&bytes)),
        author: author.clone(),
        timestamp: at,
        action: bytes,
        signature,
        entry,
    }
}

/// Records written on the shipped v1.5 by alice (a signature, its
/// revocation, its thumbnail edited once, so an Update) carried here by bob
/// with their originals:
/// each proof checks, the signer stays alice, the revocation and thumbnail
/// name bob's copy of the signature, the readers count the revocation, and a
/// second carry returns the first. Gossip reaches alice's conductor.
#[tokio::test(flavor = "multi_thread")]
async fn carried_from_v1_5_with_their_proofs() {
    let (v15, v16) = (dna_v15().await, shipped_coordinator().await);
    let mut conductors = SweetConductorBatch::standard(2).await;
    let alice15 = conductors[0].setup_app("signing15", [&v15]).await.unwrap().into_cells().remove(0);
    let alice16 = conductors[0].setup_app("signing16", [&v16]).await.unwrap().into_cells().remove(0);
    let bob16 = conductors[1].setup_app("signing16", [&v16]).await.unwrap().into_cells().remove(0);
    // Both conductors on both networks: the peer exchange waits for every
    // network on every conductor.
    let _bob15 = conductors[1].setup_app("signing15", [&v15]).await.unwrap();
    conductors.exchange_peer_info().await;
    let (a, b) = (&conductors[0], &conductors[1]);
    let (a15, a16, b16) = (alice15.zome(ZOME), alice16.zome(ZOME), bob16.zome(ZOME));

    let sig: ActionHash = a.call(&a15, "sign_and_create", sign_input(5)).await;
    let rev: ActionHash = a.call(&a15, "revoke_signature", RevokeInput { signature_action: sig.clone(), reason: Some("old".into()) }).await;
    let _: ActionHash = a.call(&a15, "set_thumbnail", SetThumbnailInput { signature_action: sig.clone(), thumbnail: "data:image/png;base64,djE1".into() }).await;
    // Edited once: its latest version is an Update, and that is carried.
    let thumb: ActionHash = a.call(&a15, "set_thumbnail", SetThumbnailInput { signature_action: sig.clone(), thumbnail: "data:image/png;base64,ZWRpdGVk".into() }).await;
    let mine: Vec<Record> = a.call(&a15, "get_my_signatures", ()).await;
    let sig_rec = mine.iter().find(|r| r.action_address() == &sig).unwrap().clone();
    let revs: Vec<Record> = a.call(&a15, "get_revocations_for_signature", sig.clone()).await;
    let rev_rec = revs.iter().find(|r| r.action_address() == &rev).unwrap().clone();
    let thumb_rec: Option<Record> = a.call(&a15, "get_thumbnail", sig.clone()).await;
    let thumb_rec = thumb_rec.unwrap();
    assert_eq!(thumb_rec.action_address(), &thumb);

    let entry: SignatureRecord = decode(&sig_rec);
    let copy: ActionHash = b.call(&b16, "carry_signature", CarrySignatureInput { record: entry.clone(), original: original_v15(&sig_rec) }).await;
    let again: ActionHash = b.call(&b16, "carry_signature", CarrySignatureInput { record: entry.clone(), original: original_v15(&sig_rec) }).await;
    assert_eq!(again, copy, "a second carry returns the first");
    let r: RevocationEntry = decode(&rev_rec);
    let rev_copy: ActionHash = b
        .call(&b16, "carry_revocation", CarryRevocationInput { signature_action: copy.clone(), revoked_at: r.revoked_at, reason: r.reason.clone(), original: original_v15(&rev_rec) })
        .await;
    let t: signing_integrity::SignatureThumbnail = decode(&thumb_rec);
    let _: ActionHash = b
        .call(&b16, "carry_thumbnail", CarryThumbnailInput { signature_action: copy.clone(), thumbnail: t.thumbnail.clone(), updated_at: t.updated_at, original: original_v15(&thumb_rec) })
        .await;

    let revs: Vec<Record> = b.call(&b16, "get_revocations_for_signature", copy.clone()).await;
    assert_eq!(revs.iter().map(|r| r.action_address().clone()).collect::<Vec<_>>(), vec![rev_copy]);
    let carried: Option<ActionHash> = b.call(&b16, "get_carried", sig.clone()).await;
    assert_eq!(carried, Some(copy.clone()));

    await_consistency([&alice16, &bob16]).await.expect("the carried records reach alice");
    let found: Vec<Record> = a.call(&a16, "get_signatures_for_hash", vec![5u8; 32]).await;
    assert_eq!(found.len(), 1);
    let copied: SignatureRecord = decode(&found[0]);
    assert_eq!(copied.signer, alice15.agent_pubkey().clone());
    assert_eq!(copied.carried_from.unwrap().witness, bob16.agent_pubkey().clone());
}

/// Records in the 0.6 shape (v1.4) carried here: a signature and its
/// revocation by the signer pass; each forged proof is refused for its own
/// reason, and so is a revocation whose original was not the signer's.
#[tokio::test(flavor = "multi_thread")]
async fn carried_from_v1_4_with_their_proofs() {
    let v16 = shipped_coordinator().await;
    let mut conductor = SweetConductor::standard().await;
    let alice = conductor.setup_app("alice", [&v16]).await.unwrap().into_cells().remove(0);
    let bob = conductor.setup_app("bob", [&v16]).await.unwrap().into_cells().remove(0);
    let (alice_key, bob_key) = (alice.agent_pubkey().clone(), bob.agent_pubkey().clone());
    let bz = bob.zome(ZOME);

    // Alice's v1.4 signature of file 4: the file signature by her key.
    let file_hash = vec![4u8; 32];
    let file_sig = conductor.keystore().sign(alice_key.clone(), file_hash.clone().into()).await.unwrap();
    let fields = SignatureV14 {
        file_hash: file_hash.clone(),
        signature: file_sig.0.to_vec(),
        signer: alice_key.clone(),
        signed_at: now_ms() - 86_400_000,
        intent: Some(signing_integrity::SigningIntent::Authorship),
        ai_generation: None,
        content_rights: None,
        integrity_report: None,
        perceptual_hash: None,
        supersedes: None,
        expires_at: None,
        tags: Some(vec!["v14".into()]),
        comment: None,
    };
    let entry_bytes = holochain_serialized_bytes::encode(&fields).unwrap();
    let at = Timestamp::from_micros((now_ms() - 86_400_000) * 1000);
    let original = original_v14(&conductor, &alice_key, 0, entry_bytes.clone(), at).await;
    let record = SignatureRecord {
        file_hash: file_hash.clone(),
        signature: file_sig.0.to_vec(),
        signer: alice_key.clone(),
        signed_at: fields.signed_at,
        intent: fields.intent.clone(),
        ai_generation: None,
        content_rights: None,
        integrity_report: None,
        perceptual_hash: None,
        supersedes: None,
        expires_at: None,
        tags: fields.tags.clone(),
        comment: None,
        carried_from: None,
    };

    // Forgeries first, each refused for its own reason.
    let carry = |record: SignatureRecord, original: Original| CarrySignatureInput { record, original };
    let mut flipped = original.clone();
    flipped.signature.0[3] ^= 1;
    let mut other_author = original.clone();
    other_author.author = bob_key.clone();
    let mut other_dna = original.clone();
    other_dna.dna = "1.5".into();
    let mut changed = record.clone();
    changed.intent = Some(signing_integrity::SigningIntent::Approval);
    for (what, input, expect) in [
        ("a flipped signature byte", carry(record.clone(), flipped), "signature does not verify"),
        ("another author", carry(record.clone(), other_author), "another author"),
        ("the wrong line", carry(record.clone(), other_dna), "does not decode"),
        ("a changed intent", carry(changed, original.clone()), "say what its original says"),
    ] {
        let r: Result<ActionHash, _> = conductor.call_fallible(&bz, "carry_signature", input).await;
        let e = format!("{:?}", r.expect_err(what));
        assert!(e.contains(expect), "{what}: {e}");
    }

    // The genuine one passes; its revocation by the signer follows.
    let copy: ActionHash = conductor.call(&bz, "carry_signature", carry(record.clone(), original.clone())).await;
    let rev_fields = RevocationV14 { signature_action: original.action_hash.clone(), revoked_at: now_ms() - 3_600_000, reason: Some("v14".into()) };
    let rev_at = Timestamp::from_micros((now_ms() - 3_600_000) * 1000);
    let rev_original = original_v14(&conductor, &alice_key, 1, holochain_serialized_bytes::encode(&rev_fields).unwrap(), rev_at).await;
    let rev_input = |original: Original| CarryRevocationInput { signature_action: copy.clone(), revoked_at: rev_fields.revoked_at, reason: rev_fields.reason.clone(), original };
    let _: ActionHash = conductor.call(&bz, "carry_revocation", rev_input(rev_original)).await;

    // A revocation whose original bob wrote (the old network accepted it from
    // anyone) is refused here.
    let bobs = original_v14(&conductor, &bob_key, 1, holochain_serialized_bytes::encode(&rev_fields).unwrap(), Timestamp::from_micros((now_ms() - 3_000_000) * 1000)).await;
    let r: Result<ActionHash, _> = conductor.call_fallible(&bz, "carry_revocation", rev_input(bobs)).await;
    let e = format!("{:?}", r.expect_err("a revocation not by the signer"));
    assert!(e.contains("Only the signer revokes"), "{e}");
}

/// Bob, on the real coordinator, cannot revoke alice's signature, edit her
/// thumbnail or file her records: the coordinator refuses some, and the
/// integrity rules refuse what a coordinator of his own would write (the
/// hostile-client test does that part).
#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_is_the_signers() {
    let v16 = shipped_coordinator().await;
    let mut conductor = SweetConductor::standard().await;
    let alice = conductor.setup_app("alice", [&v16]).await.unwrap().into_cells().remove(0);
    let bob = conductor.setup_app("bob", [&v16]).await.unwrap().into_cells().remove(0);
    let (az, bz) = (alice.zome(ZOME), bob.zome(ZOME));
    let sig: ActionHash = conductor.call(&az, "sign_and_create", sign_input(3)).await;
    let r: Result<ActionHash, _> = conductor.call_fallible(&bz, "revoke_signature", RevokeInput { signature_action: sig.clone(), reason: None }).await;
    assert!(r.is_err(), "bob cannot revoke alice's signature");
    let _: ActionHash = conductor.call(&az, "revoke_signature", RevokeInput { signature_action: sig.clone(), reason: None }).await;
}

// ── Coordinators applied over the bundle ─────────────────────────────

/// The shipped DNA with `coordinators` added or replaced (each a built wasm
/// in `../target`). Coordinators are not part of the DNA hash.
async fn dna_with(coordinators: &[(&str, &str)]) -> DnaFile {
    let mut dna = dna().await;
    let release = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/wasm32-unknown-unknown/release");
    let mut zomes = Vec::new();
    let mut wasms = Vec::new();
    for (zome, file) in coordinators {
        let bytes = std::fs::read(release.join(file)).unwrap_or_else(|_| panic!("{file} is built: cargo build --release --target wasm32-unknown-unknown -p signing_coordinator in v1.5, with build.sh's RUSTFLAGS"));
        let wasm = DnaWasm::from(bytes);
        let hash = holo_hash::WasmHash::with_data(&wasm).await;
        let def = ZomeDef::Wasm(WasmZomeDef::new(hash, Some(vec!["signing_integrity".into()])));
        zomes.push((ZomeName::from(*zome), def.into()));
        wasms.push(wasm);
    }
    dna.update_coordinators(zomes, wasms).await.unwrap();
    dna
}

/// The DNA with the coordinator the apps apply over the bundle's original
/// (this repo's, built to `../target`).
async fn shipped_coordinator() -> DnaFile {
    dna_with(&[(ZOME, "signing_coordinator.wasm")]).await
}
