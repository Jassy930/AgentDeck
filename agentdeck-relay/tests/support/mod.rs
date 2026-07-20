use std::fs;
use std::path::Path;

use agentdeck_crypto::{SigningKey, ValidatedRelayReceiptSignerIdentityV1};
use agentdeck_relay::config::RelayReceiptSigningKeyPath;

const TEST_RECEIPT_SIGNER_SEED: [u8; 32] = [0x71; 32];

#[allow(dead_code)] // 每个 integration test 独立编译本模块，纯 server 用例只需要 seed path。
pub(crate) fn test_receipt_identity() -> ValidatedRelayReceiptSignerIdentityV1 {
    ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&SigningKey::from_seed(
        &TEST_RECEIPT_SIGNER_SEED,
    ))
    .expect("fixed test receipt signer is valid")
}

#[cfg(unix)]
pub(crate) fn write_test_receipt_signing_key(parent: &Path) -> RelayReceiptSigningKeyPath {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(parent).expect("create private receipt signer directory");
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .expect("secure receipt signer directory");
    let parent = fs::canonicalize(parent).expect("canonicalize receipt signer directory");
    let path = parent.join("receipt-signing-key.seed");
    fs::write(&path, TEST_RECEIPT_SIGNER_SEED).expect("write receipt signer seed");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .expect("secure receipt signer seed");
    RelayReceiptSigningKeyPath::new(path)
}
