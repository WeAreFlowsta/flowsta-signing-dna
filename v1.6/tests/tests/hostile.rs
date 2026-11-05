//! A stranger's own coordinator (`tests/hostile`, test only) beside the
//! real one: same DNA hash, same network. On v1.6 the integrity rules refuse
//! each write it tries, so the writer's own conductor refuses to commit it.
//!
//! Build first, with build.sh's RUSTFLAGS: `cargo build --release --target
//! wasm32-unknown-unknown` in `v1.6`, and the same in `tests/hostile` with
//! `CARGO_TARGET_DIR=../../target`.

use holochain::prelude::*;
use holochain::sweettest::*;
use signing_coordinator::{SetThumbnailInput, SignAndCreateInput};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const ZOME: &str = "signing";

async fn dna_with(coordinators: &[(&str, &str)]) -> DnaFile {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../workdir/flowsta_signing_v1_6.dna");
    let mut dna = SweetDnaFile::from_bundle(&path).await.expect("v1.6/workdir/flowsta_signing_v1_6.dna loads");
    let release = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/wasm32-unknown-unknown/release");
    let mut zomes = Vec::new();
    let mut wasms = Vec::new();
    for (zome, file) in coordinators {
        let wasm = DnaWasm::from(std::fs::read(release.join(file)).unwrap_or_else(|_| panic!("{file} is built")));
        let hash = holo_hash::WasmHash::with_data(&wasm).await;
        zomes.push((ZomeName::from(*zome), ZomeDef::Wasm(WasmZomeDef::new(hash, Some(vec!["signing_integrity".into()]))).into()));
        wasms.push(wasm);
    }
    dna.update_coordinators(zomes, wasms).await.unwrap();
    dna
}

fn sign_input(hash_byte: u8) -> SignAndCreateInput {
    SignAndCreateInput {
        file_hash: vec![hash_byte; 32],
        signed_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64,
        intent: None,
        ai_generation: None,
        content_rights: None,
        integrity_report: None,
        perceptual_hash: None,
        supersedes: None,
        expires_at: None,
        tags: None,
        comment: None,
    }
}

#[derive(serde::Serialize, Debug)]
struct FileLinkInput {
    file_hash: Vec<u8>,
    signature_action: ActionHash,
}

#[derive(serde::Serialize, Debug)]
struct AgentLinkInput {
    agent: AgentPubKey,
    signature_action: ActionHash,
}

#[derive(serde::Serialize, Debug)]
struct ThumbnailUpdateInput {
    thumbnail_action: ActionHash,
    signature_action: ActionHash,
}

#[tokio::test(flavor = "multi_thread")]
async fn a_strangers_writes_are_refused() {
    let ours = dna_with(&[(ZOME, "signing_coordinator.wasm")]).await;
    let hostile = dna_with(&[(ZOME, "signing_coordinator.wasm"), ("hostile", "signing_hostile_test.wasm")]).await;
    assert_eq!(ours.dna_hash(), hostile.dna_hash());
    let mut conductor = SweetConductor::standard().await;
    let alice = conductor.setup_app("alice", [&ours]).await.unwrap().into_cells().remove(0);
    let mallory = conductor.setup_app("mallory", [&hostile]).await.unwrap().into_cells().remove(0);
    let (az, mz, mh) = (alice.zome(ZOME), mallory.zome(ZOME), mallory.zome("hostile"));
    let alice_key = alice.agent_pubkey().clone();

    let sig7: ActionHash = conductor.call(&az, "sign_and_create", sign_input(7)).await;
    let thumb: ActionHash = conductor
        .call(&az, "set_thumbnail", SetThumbnailInput { signature_action: sig7.clone(), thumbnail: "data:image/png;base64,QUxJQ0U=".into() })
        .await;
    let sig8: ActionHash = conductor.call(&mz, "sign_and_create", sign_input(8)).await;

    async fn refused<I: serde::Serialize + std::fmt::Debug>(conductor: &SweetConductor, zome: &SweetZome, f: &str, input: I, expect: &str) {
        let r: Result<ActionHash, _> = conductor.call_fallible(zome, f, input).await;
        let e = format!("{:?}", r.expect_err(f));
        assert!(e.contains(expect), "{f}: expected \"{expect}\", got {e}");
    }
    refused(&conductor, &mh, "forge_revocation", sig7.clone(), "Only the signer revokes").await;
    refused(&conductor, &mh, "delete_record", sig7.clone(), "never deleted").await;
    refused(&conductor, &mh, "update_thumbnail", ThumbnailUpdateInput { thumbnail_action: thumb.clone(), signature_action: sig7.clone() }, "Only a thumbnail's author updates it").await;
    refused(&conductor, &mh, "link_file", FileLinkInput { file_hash: vec![9; 32], signature_action: sig7.clone() }, "filed by its own author").await;
    refused(&conductor, &mh, "link_agent", AgentLinkInput { agent: alice_key.clone(), signature_action: sig8.clone() }, "from the base its record names").await;
    let r: Result<u32, _> = conductor.call_fallible(&mh, "remove_file_links", vec![7u8; 32]).await;
    let e = format!("{:?}", r.expect_err("remove_file_links"));
    assert!(e.contains("never removed"), "remove_file_links: {e}");
}
