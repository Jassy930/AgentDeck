// agentdeck-relay/src/auth/enroll.rs
//! Challenge-response enroll——纯函数，注入 store/时钟/secret；不含网络。

use crate::auth::crypto;
use crate::auth::store::{Account, Challenge, Device, DeviceRole, RelayStore};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum EnrollError {
    #[error("bad bootstrap secret")]
    BadSecret,
    #[error("challenge missing, expired, or already used")]
    ChallengeExpired,
    #[error("ed25519 signature verification failed")]
    BadSignature,
    /// 首次 enroll（singleton account 尚未建立）必须提供 owner_pubkey 才能派生 account_id。
    /// brief 未列此变体，但复用 BadSignature 语义不符（这不是签名失败）；新增以准确表达失败原因。
    #[error("owner_pubkey required to create the first (singleton) account")]
    MissingOwnerPubkey,
}

#[derive(Debug, Clone)]
pub(crate) struct ChallengeReq {
    pub device_sign_pubkey: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ChallengeResp {
    pub nonce: String,
}

#[derive(Debug, Clone)]
pub(crate) struct NewDevice {
    pub device_id: String,
    pub role: DeviceRole,
    pub sign_pubkey: String,
    pub box_pubkey: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CompleteReq {
    pub bootstrap_secret: String,
    pub nonce_sig: String,
    pub device: NewDevice,
    pub owner_pubkey: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct CompleteResp {
    pub account_id: String,
    pub credential: String,
    pub device: Device,
}

/// 发起 challenge：生成 nonce、存入 store（同一 device_sign_pubkey 重复调用覆盖旧 challenge）。
pub(crate) fn start_challenge<S: RelayStore>(
    store: &mut S,
    req: ChallengeReq,
    ttl_ms: i64,
    now_ms: i64,
) -> ChallengeResp {
    let nonce = crypto::new_challenge_nonce();
    store.put_challenge(Challenge {
        device_sign_pubkey: req.device_sign_pubkey,
        nonce: nonce.clone(),
        expires_at_ms: now_ms + ttl_ms,
        used: false,
    });
    ChallengeResp { nonce }
}

/// account_id 确定性派生：sha256(owner_pubkey) 的 b64 前 16 字符加前缀。
/// 只在 singleton account 尚未创建时调用一次；后续设备加入沿用已存在的 account_id。
fn derive_account_id(owner_pubkey: &str) -> String {
    let h = crypto::hash_credential(owner_pubkey);
    format!("acc-{}", &h[..16.min(h.len())])
}

/// 完成 enroll：校验 secret → 单次消费 challenge → 验签 → 建/取 singleton account → 落 device
/// （credential_hash）→ 返回明文 credential 一次性。
pub(crate) fn complete<S: RelayStore>(
    store: &mut S,
    req: CompleteReq,
    bootstrap_secret: &str,
    now_ms: i64,
) -> Result<CompleteResp, EnrollError> {
    if req.bootstrap_secret != bootstrap_secret {
        return Err(EnrollError::BadSecret);
    }
    let challenge = store
        .take_challenge(&req.device.sign_pubkey, now_ms)
        .ok_or(EnrollError::ChallengeExpired)?;
    if !crypto::verify_ed25519(
        &req.device.sign_pubkey,
        challenge.nonce.as_bytes(),
        &req.nonce_sig,
    ) {
        return Err(EnrollError::BadSignature);
    }
    let account_id = match store.singleton_account() {
        Some(account) => account.account_id.clone(),
        None => {
            let owner_pubkey = req
                .owner_pubkey
                .as_deref()
                .ok_or(EnrollError::MissingOwnerPubkey)?;
            let account_id = derive_account_id(owner_pubkey);
            store.create_account(Account {
                account_id: account_id.clone(),
                owner_sign_pubkey: owner_pubkey.to_string(),
            });
            account_id
        }
    };
    let credential = crypto::gen_credential();
    let device = Device {
        device_id: req.device.device_id,
        account_id: account_id.clone(),
        role: req.device.role,
        credential_hash: crypto::hash_credential(&credential),
        sign_pubkey: req.device.sign_pubkey,
        box_pubkey: req.device.box_pubkey,
        revoked: false,
    };
    store.put_device(device.clone());
    Ok(CompleteResp {
        account_id,
        credential,
        device,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::crypto;
    use crate::auth::store::{DeviceRole, InMemoryRelayStore};
    use ed25519_dalek::Signer; // 需要 trait 在 scope 内才能调用 SigningKey::sign（brief 测试片段未列，编译要求补）

    fn dev_keys() -> (String, ed25519_dalek::SigningKey) {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        (crypto::b64(sk.verifying_key().as_bytes()), sk)
    }

    #[test]
    fn enroll_creates_singleton_account_then_joins_it() {
        let mut store = InMemoryRelayStore::default();
        let secret = "boot-secret";
        // 设备1（device 角色）
        let (dpub, dsk) = dev_keys();
        let ch = start_challenge(
            &mut store,
            ChallengeReq {
                device_sign_pubkey: dpub.clone(),
            },
            60_000,
            1_000,
        );
        let sig = crypto::b64(&dsk.sign(ch.nonce.as_bytes()).to_bytes());
        let r1 = complete(
            &mut store,
            CompleteReq {
                bootstrap_secret: secret.into(),
                nonce_sig: sig,
                device: NewDevice {
                    device_id: "d1".into(),
                    role: DeviceRole::Device,
                    sign_pubkey: dpub.clone(),
                    box_pubkey: "box1".into(),
                },
                owner_pubkey: Some("owner-pub".into()),
            },
            secret,
            2_000,
        )
        .unwrap();
        let acc = r1.account_id.clone();
        // 设备2（machine 角色）——同 bootstrap secret，应加入同一 account、不新建
        let (mpub, msk) = dev_keys();
        let ch2 = start_challenge(
            &mut store,
            ChallengeReq {
                device_sign_pubkey: mpub.clone(),
            },
            60_000,
            3_000,
        );
        let sig2 = crypto::b64(&msk.sign(ch2.nonce.as_bytes()).to_bytes());
        let r2 = complete(
            &mut store,
            CompleteReq {
                bootstrap_secret: secret.into(),
                nonce_sig: sig2,
                device: NewDevice {
                    device_id: "m1".into(),
                    role: DeviceRole::Machine,
                    sign_pubkey: mpub,
                    box_pubkey: "box2".into(),
                },
                owner_pubkey: None,
            },
            secret,
            4_000,
        )
        .unwrap();
        assert_eq!(r2.account_id, acc, "第二设备必须加入同一 singleton account");
        assert_eq!(store.account_count(), 1);
        assert!(
            crypto::hash_credential(&r1.credential)
                == store.device(&r1.device.device_id).unwrap().credential_hash
        );
    }

    #[test]
    fn enroll_rejects_bad_secret_expired_and_reused_nonce() {
        let mut store = InMemoryRelayStore::default();
        let (dpub, dsk) = dev_keys();
        let ch = start_challenge(
            &mut store,
            ChallengeReq {
                device_sign_pubkey: dpub.clone(),
            },
            60_000,
            1_000,
        );
        let sig = crypto::b64(&dsk.sign(ch.nonce.as_bytes()).to_bytes());
        let good = CompleteReq {
            bootstrap_secret: "boot".into(),
            nonce_sig: sig.clone(),
            device: NewDevice {
                device_id: "d1".into(),
                role: DeviceRole::Device,
                sign_pubkey: dpub.clone(),
                box_pubkey: "b".into(),
            },
            owner_pubkey: Some("o".into()),
        };
        // 错 secret
        assert!(matches!(
            complete(&mut store, good.clone(), "WRONG", 2_000),
            Err(EnrollError::BadSecret)
        ));
        // TTL 过期
        assert!(matches!(
            complete(&mut store, good.clone(), "boot", 999_999),
            Err(EnrollError::ChallengeExpired)
        ));
        // 正常一次
        complete(&mut store, good.clone(), "boot", 2_000).unwrap();
        // nonce 重用（已消费）
        assert!(matches!(
            complete(&mut store, good, "boot", 2_000),
            Err(EnrollError::ChallengeExpired)
        ));
    }
}
