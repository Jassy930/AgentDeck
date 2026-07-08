// agentdeck-relay/src/auth/crypto.rs
//! ed25519 签名验证 + sha2 hash + CSPRNG nonce/credential 生成。纯函数，无 panic。

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

pub fn b64(bytes: &[u8]) -> String { STANDARD.encode(bytes) }
pub fn unb64(s: &str) -> Option<Vec<u8>> { STANDARD.decode(s.as_bytes()).ok() }

pub fn new_challenge_nonce() -> String {
    use rand::RngCore;
    let mut n = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut n);
    b64(&n)
}
pub fn gen_credential() -> String {
    use rand::RngCore;
    let mut c = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut c);
    b64(&c)
}
pub fn hash_credential(cred: &str) -> String {
    let mut h = Sha256::new();
    h.update(cred.as_bytes());
    b64(&h.finalize())
}
pub fn verify_ed25519(pubkey_b64: &str, msg: &[u8], sig_b64: &str) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let (Some(pk), Some(sig)) = (unb64(pubkey_b64), unb64(sig_b64)) else { return false };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk.as_slice()) else { return false };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig.as_slice()) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else { return false };
    vk.verify_strict(msg, &Signature::from_bytes(&sig_arr)).is_ok()
}
