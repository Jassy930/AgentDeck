//! Persistent remote CLI 的唯一 machine selector。
//!
//! 选择器只接受 PairedMachineStore 的稳定复合身份：MachineRoot fingerprint 与 machine route。
//! display name、device route 或 Relay URL 都不是 machine identity，不能参与选择或回退。

use std::fmt;

use agentdeck_protocol::relay_v2::MachineRouteId;
use agentdeck_protocol::runtime::MachineRootFingerprint;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use thiserror::Error;

use super::paired_machine::PairedMachineIdentity;

/// 已完成 canonical 解码的 persistent paired-machine selector。
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PersistentMachineSelector {
    identity: PairedMachineIdentity,
}

impl fmt::Debug for PersistentMachineSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersistentMachineSelector([REDACTED])")
    }
}

impl PersistentMachineSelector {
    /// 从两项 STANDARD padded base64 参数构造唯一 paired-machine identity。
    pub fn parse(
        machine_root_fingerprint: &str,
        machine_route: &str,
    ) -> Result<Self, PersistentMachineSelectorError> {
        let root = decode_canonical::<32>(machine_root_fingerprint)
            .ok_or(PersistentMachineSelectorError::InvalidMachineRootFingerprint)?;
        let route = decode_canonical::<16>(machine_route)
            .ok_or(PersistentMachineSelectorError::InvalidMachineRoute)?;
        Ok(Self {
            identity: PairedMachineIdentity::new(
                MachineRootFingerprint::from_bytes(root),
                MachineRouteId::from_bytes(route),
            ),
        })
    }

    #[must_use]
    pub const fn identity(self) -> PairedMachineIdentity {
        self.identity
    }
}

/// Selector 解析错误不携带或回显用户提供的 route/fingerprint 原文。
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum PersistentMachineSelectorError {
    #[error(
        "--machine-root-fingerprint must be canonical padded STANDARD base64 for exactly 32 bytes"
    )]
    InvalidMachineRootFingerprint,
    #[error("--machine-route must be canonical padded STANDARD base64 for exactly 16 bytes")]
    InvalidMachineRoute,
}

fn decode_canonical<const N: usize>(value: &str) -> Option<[u8; N]> {
    let expected_encoded_len = N.div_ceil(3).checked_mul(4)?;
    if value.len() != expected_encoded_len {
        return None;
    }
    let decoded = STANDARD.decode(value.as_bytes()).ok()?;
    if STANDARD.encode(&decoded) != value {
        return None;
    }
    decoded.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_standard_base64_constructs_the_exact_paired_identity() {
        let root = [0x11; 32];
        let route = [0x22; 16];
        let selector =
            PersistentMachineSelector::parse(&STANDARD.encode(root), &STANDARD.encode(route))
                .expect("canonical persistent machine selector");

        assert_eq!(
            selector.identity(),
            PairedMachineIdentity::new(
                MachineRootFingerprint::from_bytes(root),
                MachineRouteId::from_bytes(route),
            )
        );
    }

    #[test]
    fn url_safe_no_pad_wrong_length_and_non_canonical_values_are_rejected() {
        let root = STANDARD.encode([0xff; 32]);
        let route = STANDARD.encode([0xff; 16]);
        let short_root = STANDARD.encode([0x11; 31]);
        let short_route = STANDARD.encode([0x22; 15]);
        let oversized_route = "A".repeat(64 * 1024);
        let cases = [
            (
                "__________________________________________8",
                route.as_str(),
            ),
            (root.trim_end_matches('='), route.as_str()),
            (root.as_str(), "_____________________w"),
            (root.as_str(), route.trim_end_matches('=')),
            (short_root.as_str(), route.as_str()),
            (root.as_str(), short_route.as_str()),
            (root.as_str(), "/////////////////////x=="),
            (root.as_str(), oversized_route.as_str()),
        ];

        for (candidate_root, candidate_route) in cases {
            assert!(
                PersistentMachineSelector::parse(candidate_root, candidate_route).is_err(),
                "selector must reject a non-canonical or wrong-length component"
            );
        }
    }

    #[test]
    fn selector_debug_and_errors_never_expose_raw_route_material() {
        let root = STANDARD.encode([0x33; 32]);
        let route = STANDARD.encode([0x44; 16]);
        let selector = PersistentMachineSelector::parse(&root, &route).expect("valid selector");
        let debug = format!("{selector:?}");
        assert_eq!(debug, "PersistentMachineSelector([REDACTED])");
        assert!(!debug.contains(&root));
        assert!(!debug.contains(&route));

        let invalid_route = "route-secret-sentinel";
        let error = PersistentMachineSelector::parse(&root, invalid_route)
            .expect_err("invalid route must fail");
        assert!(!error.to_string().contains(invalid_route));
        assert!(!format!("{error:?}").contains(invalid_route));
    }
}
