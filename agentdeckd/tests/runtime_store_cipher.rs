use std::fs;
use std::path::PathBuf;

use agentdeckd::runtime::store::cipher::{
    CipherError, KeyWrapAad, ROW_BLOB_V1_HEADER_LEN, RowAad, RuntimeKeyBundle,
    WRAPPED_KEY_BUNDLE_V1_LEN,
};
use agentdeckd::runtime::store::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_VERSION};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

fn storage_kek(label: &str) -> StorageKek {
    let path = PathBuf::from("/tmp").join(format!(
        "agentdeck-row-cipher-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    fs::create_dir(&path).expect("create isolated key test directory");
    let key = load_or_create_storage_kek(&MemoryKeyStore::new(), &path.join("runtime.db"))
        .expect("create StorageKEK");
    fs::remove_dir(&path).expect("remove isolated key test directory");
    key
}

fn aad<'a>(database_id: &'a [u8], primary_key: &'a [u8]) -> RowAad<'a> {
    RowAad {
        schema_family: b"runtime",
        schema_version: 1,
        database_id,
        table: b"commands",
        primary_key,
        column: b"prompt",
    }
}

fn key_aad(database_id: &[u8]) -> KeyWrapAad<'_> {
    KeyWrapAad {
        schema_family: b"agentdeck-runtime",
        schema_version: 1,
        database_id,
    }
}

#[test]
fn fresh_bundle_wraps_with_storage_kek_and_roundtrips() {
    let kek = storage_kek("roundtrip");
    let database_id = b"database-id-0001";
    let bundle = RuntimeKeyBundle::fresh(7).expect("fresh runtime key bundle");

    let wrapped = bundle
        .wrap(&kek, &key_aad(database_id))
        .expect("wrap key bundle");
    let restored =
        RuntimeKeyBundle::unwrap(&kek, &key_aad(database_id), &wrapped).expect("unwrap key bundle");

    assert_eq!(wrapped.len(), WRAPPED_KEY_BUNDLE_V1_LEN);
    assert_eq!(&wrapped[..4], b"ADKB");
    assert_eq!(wrapped[4], 1);
    assert_eq!(restored.generation(), 7);
    let context = aad(database_id, b"command-1");
    let sealed = bundle
        .row_cipher()
        .seal(&context, b"same keys survive wrapping")
        .expect("seal with original");
    let opened = restored
        .row_cipher()
        .open(&context, &sealed)
        .expect("open with restored");
    assert_eq!(opened.expose_secret(), b"same keys survive wrapping");
    assert_eq!(
        bundle
            .blind_index(b"command.idempotency", b"lookup")
            .expect("original index"),
        restored
            .blind_index(b"command.idempotency", b"lookup")
            .expect("restored index")
    );
}

#[test]
fn key_bundle_wrap_uses_a_fresh_nonce_and_hides_key_material() {
    let kek = storage_kek("wrap-nonce");
    let database_id = b"database-id-0001";
    let bundle = RuntimeKeyBundle::fresh(1).expect("fresh runtime key bundle");

    let first = bundle
        .wrap(&kek, &key_aad(database_id))
        .expect("first wrap");
    let second = bundle
        .wrap(&kek, &key_aad(database_id))
        .expect("second wrap");

    assert_ne!(first, second);
    assert_ne!(&first[12..24], &second[12..24]);
    assert_eq!(first.len(), WRAPPED_KEY_BUNDLE_V1_LEN);
    assert_eq!(second.len(), WRAPPED_KEY_BUNDLE_V1_LEN);
}

#[test]
fn wrapped_bundle_rejects_tamper_wrong_kek_and_wrong_database() {
    let kek = storage_kek("right");
    let wrong_kek = storage_kek("wrong");
    let database_id = b"database-id-0001";
    let bundle = RuntimeKeyBundle::fresh(2).expect("fresh runtime key bundle");
    let wrapped = bundle
        .wrap(&kek, &key_aad(database_id))
        .expect("wrap key bundle");

    assert!(matches!(
        RuntimeKeyBundle::unwrap(&wrong_kek, &key_aad(database_id), &wrapped),
        Err(CipherError::AuthenticationFailed)
    ));
    assert!(matches!(
        RuntimeKeyBundle::unwrap(&kek, &key_aad(b"database-id-0002"), &wrapped),
        Err(CipherError::AuthenticationFailed)
    ));
    let wrong_family = KeyWrapAad {
        schema_family: b"another-runtime",
        ..key_aad(database_id)
    };
    assert!(matches!(
        RuntimeKeyBundle::unwrap(&kek, &wrong_family, &wrapped),
        Err(CipherError::AuthenticationFailed)
    ));
    let wrong_version = KeyWrapAad {
        schema_version: 2,
        ..key_aad(database_id)
    };
    assert!(matches!(
        RuntimeKeyBundle::unwrap(&kek, &wrong_version, &wrapped),
        Err(CipherError::AuthenticationFailed)
    ));

    for offset in [8, 12, WRAPPED_KEY_BUNDLE_V1_LEN - 1] {
        let mut tampered = wrapped.clone();
        tampered[offset] ^= 0x40;
        assert!(RuntimeKeyBundle::unwrap(&kek, &key_aad(database_id), &tampered).is_err());
    }
}

#[test]
fn row_blob_has_a_fixed_v1_header_and_random_nonce() {
    let database_id = b"database-id-0001";
    let bundle = RuntimeKeyBundle::fresh(9).expect("fresh runtime key bundle");
    let context = aad(database_id, b"command-1");

    let first = bundle
        .row_cipher()
        .seal(&context, b"do not persist this sentinel")
        .expect("first seal");
    let second = bundle
        .row_cipher()
        .seal(&context, b"do not persist this sentinel")
        .expect("second seal");

    assert_eq!(&first[..4], b"ADRB");
    assert_eq!(first[4], 1);
    assert_eq!(&first[8..12], &9_u32.to_be_bytes());
    assert_eq!(first.len(), ROW_BLOB_V1_HEADER_LEN + 28 + 16);
    assert_ne!(&first[12..24], &second[12..24]);
    assert_ne!(first, second);
    assert!(
        !first
            .windows(b"do not persist this sentinel".len())
            .any(|window| window == b"do not persist this sentinel")
    );

    let opened = bundle
        .row_cipher()
        .open(&context, &first)
        .expect("open sealed row");
    assert_eq!(opened.expose_secret(), b"do not persist this sentinel");
}

#[test]
fn row_blob_rejects_tamper_and_wrong_aad_component() {
    let database_id = b"database-id-0001";
    let bundle = RuntimeKeyBundle::fresh(3).expect("fresh runtime key bundle");
    let context = aad(database_id, b"command-1");
    let blob = bundle
        .row_cipher()
        .seal(&context, b"sensitive prompt")
        .expect("seal row");

    let mut tampered = blob.clone();
    *tampered.last_mut().expect("tag byte") ^= 1;
    assert!(matches!(
        bundle.row_cipher().open(&context, &tampered),
        Err(CipherError::AuthenticationFailed)
    ));

    let wrong_contexts = [
        RowAad {
            schema_family: b"other",
            ..context
        },
        RowAad {
            schema_version: 2,
            ..context
        },
        RowAad {
            database_id: b"database-id-0002",
            ..context
        },
        RowAad {
            table: b"conversations",
            ..context
        },
        RowAad {
            primary_key: b"command-2",
            ..context
        },
        RowAad {
            column: b"title",
            ..context
        },
    ];
    for wrong in wrong_contexts {
        assert!(matches!(
            bundle.row_cipher().open(&wrong, &blob),
            Err(CipherError::AuthenticationFailed)
        ));
    }
}

#[test]
fn swapping_ciphertext_between_rows_is_rejected() {
    let database_id = b"database-id-0001";
    let bundle = RuntimeKeyBundle::fresh(4).expect("fresh runtime key bundle");
    let first_row = aad(database_id, b"command-1");
    let second_row = aad(database_id, b"command-2");
    let first_blob = bundle
        .row_cipher()
        .seal(&first_row, b"first row")
        .expect("seal first row");

    assert!(matches!(
        bundle.row_cipher().open(&second_row, &first_blob),
        Err(CipherError::AuthenticationFailed)
    ));
}

#[test]
fn aad_and_blind_index_length_prefixes_prevent_field_boundary_collisions() {
    let database_id = b"database-id-0001";
    let bundle = RuntimeKeyBundle::fresh(12).expect("fresh runtime key bundle");
    // 若只做裸拼接，两组 table + primary-key 都是 `abc`。
    let first = RowAad {
        table: b"ab",
        primary_key: b"c",
        ..aad(database_id, b"unused")
    };
    let shifted_boundary = RowAad {
        table: b"a",
        primary_key: b"bc",
        ..first
    };
    let blob = bundle
        .row_cipher()
        .seal(&first, b"boundary-bound")
        .expect("seal first field split");

    assert!(matches!(
        bundle.row_cipher().open(&shifted_boundary, &blob),
        Err(CipherError::AuthenticationFailed)
    ));
    assert_ne!(
        bundle
            .blind_index(b"ab", b"c")
            .expect("first blind field split"),
        bundle
            .blind_index(b"a", b"bc")
            .expect("second blind field split")
    );
}

#[test]
fn row_generation_is_checked_before_decryption() {
    let database_id = b"database-id-0001";
    let first = RuntimeKeyBundle::fresh(1).expect("first generation");
    let second = RuntimeKeyBundle::fresh(2).expect("second generation");
    let context = aad(database_id, b"command-1");
    let blob = first
        .row_cipher()
        .seal(&context, b"generation-bound")
        .expect("seal row");

    assert!(matches!(
        second.row_cipher().open(&context, &blob),
        Err(CipherError::GenerationMismatch {
            expected: 2,
            actual: 1
        })
    ));
}

#[test]
fn row_cipher_enforces_column_specific_length_before_allocating_plaintext() {
    let database_id = b"database-id-0001";
    let bundle = RuntimeKeyBundle::fresh(1).expect("fresh runtime key bundle");
    let context = aad(database_id, b"command-1");
    let at_limit = bundle
        .row_cipher()
        .seal_bounded(&context, b"12345678", 8)
        .expect("seal at limit");
    assert_eq!(
        bundle
            .row_cipher()
            .open_bounded(&context, &at_limit, 8)
            .expect("open at limit")
            .expose_secret(),
        b"12345678"
    );
    assert!(matches!(
        bundle.row_cipher().seal_bounded(&context, b"123456789", 8),
        Err(CipherError::InputTooLarge)
    ));
    assert!(matches!(
        bundle.row_cipher().open_bounded(&context, &at_limit, 7),
        Err(CipherError::InputTooLarge)
    ));
}

#[test]
fn blind_index_is_deterministic_and_domain_separated() {
    let bundle = RuntimeKeyBundle::fresh(5).expect("fresh runtime key bundle");

    let first = bundle
        .blind_index(b"command.idempotency", b"same-value")
        .expect("first index");
    let repeated = bundle
        .blind_index(b"command.idempotency", b"same-value")
        .expect("repeated index");
    let other_domain = bundle
        .blind_index(b"conversation.lookup", b"same-value")
        .expect("other domain index");
    let other_value = bundle
        .blind_index(b"command.idempotency", b"other-value")
        .expect("other value index");

    assert_eq!(first, repeated);
    assert_ne!(first, other_domain);
    assert_ne!(first, other_value);
    assert_eq!(first.as_bytes().len(), 32);
    assert_eq!(format!("{first:?}"), "BlindIndex([REDACTED])");
}

#[test]
fn malformed_versions_and_empty_contexts_fail_closed() {
    let kek = storage_kek("malformed");
    let database_id = b"database-id-0001";
    let bundle = RuntimeKeyBundle::fresh(6).expect("fresh runtime key bundle");
    let wrapped = bundle
        .wrap(&kek, &key_aad(database_id))
        .expect("wrap key bundle");
    let context = aad(database_id, b"command-1");
    let blob = bundle
        .row_cipher()
        .seal(&context, b"secret")
        .expect("seal row");

    assert!(matches!(
        RuntimeKeyBundle::unwrap(&kek, &key_aad(database_id), &wrapped[..20]),
        Err(CipherError::InvalidEncoding)
    ));
    let mut unsupported_bundle = wrapped;
    unsupported_bundle[4] = 2;
    assert!(matches!(
        RuntimeKeyBundle::unwrap(&kek, &key_aad(database_id), &unsupported_bundle),
        Err(CipherError::UnsupportedVersion { actual: 2 })
    ));
    assert!(matches!(
        bundle.row_cipher().open(&context, &blob[..20]),
        Err(CipherError::InvalidEncoding)
    ));
    let mut unsupported_row = blob;
    unsupported_row[4] = 2;
    assert!(matches!(
        bundle.row_cipher().open(&context, &unsupported_row),
        Err(CipherError::UnsupportedVersion { actual: 2 })
    ));

    let empty_table = RowAad {
        table: b"",
        ..context
    };
    assert!(matches!(
        bundle.row_cipher().seal(&empty_table, b"secret"),
        Err(CipherError::InvalidContext("table"))
    ));
    assert!(matches!(
        bundle.blind_index(b"", b"value"),
        Err(CipherError::InvalidContext("blind-index domain"))
    ));
    assert!(matches!(
        RuntimeKeyBundle::fresh(0),
        Err(CipherError::InvalidGeneration)
    ));
}

#[test]
fn secret_bearing_types_have_redacted_debug_output() {
    let bundle = RuntimeKeyBundle::fresh(11).expect("fresh runtime key bundle");
    let cipher = bundle.row_cipher();
    let context = aad(b"database-id-0001", b"sensitive-primary-key");
    let key_context = key_aad(b"database-id-0001");

    assert_eq!(
        format!("{bundle:?}"),
        "RuntimeKeyBundle { generation: 11, keys: [REDACTED] }"
    );
    assert_eq!(
        format!("{cipher:?}"),
        "RowCipher { generation: 11, key: [REDACTED] }"
    );
    assert_eq!(
        format!("{context:?}"),
        "RowAad { schema_version: 1, fields: [REDACTED] }"
    );
    assert_eq!(
        format!("{key_context:?}"),
        "KeyWrapAad { schema_version: 1, fields: [REDACTED] }"
    );
}

#[test]
fn physical_schema_upgrade_does_not_rotate_the_crypto_context() {
    assert_eq!(RUNTIME_SCHEMA_VERSION, 8);
    assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
}
