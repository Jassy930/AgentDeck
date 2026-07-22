use agentdeck_crypto::{SecretAeadKey, derive_nonce_prefix};

#[test]
fn both_rust_endpoints_derive_the_same_stable_prefix_without_exposing_the_key() {
    let random_key = [
        0x7a, 0x03, 0xe1, 0x94, 0xb5, 0x2f, 0x68, 0xc0, 0x11, 0xda, 0x43, 0x8e, 0xf7, 0x29, 0x55,
        0xbc, 0x61, 0xa8, 0x0d, 0x37, 0x9f, 0xe4, 0x72, 0x16, 0xc9, 0x5b, 0x24, 0x83, 0x40, 0xed,
        0x9a, 0x6f,
    ];
    let machine_copy = SecretAeadKey::from_bytes(random_key);
    let device_copy = SecretAeadKey::from_bytes(random_key);

    let machine_prefix = derive_nonce_prefix(&machine_copy);
    let device_prefix = derive_nonce_prefix(&device_copy);
    assert_eq!(machine_prefix, [0x52, 0xd0, 0x1c, 0x68]);
    assert_eq!(machine_prefix, device_prefix);
    assert_eq!(machine_prefix, derive_nonce_prefix(&machine_copy));

    let mut different_key = random_key;
    different_key[17] ^= 0x80;
    assert_ne!(
        machine_prefix,
        derive_nonce_prefix(&SecretAeadKey::from_bytes(different_key)),
        "independent random AEAD keys must not share the deterministic test projection"
    );
    assert!(!format!("{machine_copy:?}").contains("7a03e194"));
}
