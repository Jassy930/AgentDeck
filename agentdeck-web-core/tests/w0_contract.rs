use std::path::Path;

use agentdeck_web_core::{
    crypto_tamper_is_rejected, relay_hello_bytes, runtime_request_roundtrip, validate_relay_frame,
    w0_contract_snapshot, w0_negative_snapshot,
};

fn runtime_request_fixture() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../protocol/agentdeck/fixtures/runtime-v5-wire.jsonl");
    let source = std::fs::read_to_string(path).expect("read Runtime v5 fixture");
    let value = source
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid fixture line"))
        .find(|line| line["case"] == "requestMachineRemoteStatus")
        .expect("request fixture")["value"]
        .clone();
    serde_json::to_vec(&value).expect("encode fixture value")
}

#[test]
fn reuses_relay_runtime_and_crypto_contracts() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../protocol/agentdeck/crypto-vectors-v1.json"
    ))
    .expect("valid crypto vectors");
    let snapshot = w0_contract_snapshot().expect("W0 snapshot");

    assert_eq!(
        snapshot.relay_hello_hex, "4144525632000200000002",
        "Relay Hello 必须复用 current binary codec"
    );
    assert_eq!(
        snapshot.sha256_hex, vectors["sha256"]["digestHex"],
        "SHA-256 KAT 必须与共享事实源一致"
    );
    assert_eq!(snapshot.tbs_hex, vectors["tbs_canonical"]["encodedHex"]);
    assert_eq!(
        snapshot.ed25519_public_key_hex,
        vectors["ed25519"]["publicKeyHex"]
    );
    assert_eq!(
        snapshot.ed25519_signature_hex,
        vectors["ed25519"]["signatureHex"]
    );
    assert_eq!(
        snapshot.aead_nonce_hex,
        vectors["chacha20poly1305"]["nonceHex"]
    );
    assert_eq!(
        snapshot.aead_ciphertext_hex,
        vectors["chacha20poly1305"]["ciphertextHex"]
    );
    assert_eq!(snapshot.hpke_info_hex, vectors["hpke_base_kat"]["infoHex"]);
    assert_eq!(
        snapshot.hpke_recipient_public_hex,
        vectors["hpke_base_kat"]["recipientPubHex"]
    );
    assert_eq!(snapshot.hpke_enc_hex, vectors["hpke_base_kat"]["encHex"]);
    assert_eq!(
        snapshot.hpke_ciphertext_hex,
        vectors["hpke_base_kat"]["ciphertextHex"]
    );

    let hello = relay_hello_bytes();
    validate_relay_frame(&hello).expect("current Relay frame");
    let mut bad_magic = hello;
    bad_magic[0] ^= 0xff;
    assert!(validate_relay_frame(&bad_magic).is_err());

    let runtime = runtime_request_fixture();
    let roundtrip = runtime_request_roundtrip(&runtime).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&roundtrip).unwrap(),
        serde_json::from_slice::<serde_json::Value>(&runtime).unwrap()
    );
    let mut invalid: serde_json::Value = serde_json::from_slice(&runtime).unwrap();
    invalid["unexpected"] = serde_json::json!(true);
    assert!(runtime_request_roundtrip(&serde_json::to_vec(&invalid).unwrap()).is_err());

    assert!(crypto_tamper_is_rejected().expect("crypto tamper contract"));
    let negatives = w0_negative_snapshot().expect("negative crypto contract");
    assert!(negatives.ed25519_signature_tamper_rejected);
    assert!(negatives.hpke_ciphertext_tamper_rejected);
    assert!(negatives.hpke_info_tamper_rejected);
    assert!(negatives.hpke_aad_tamper_rejected);
}
