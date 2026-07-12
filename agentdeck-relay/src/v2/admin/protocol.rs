//! 本机 admin socket 的有界 JSONL 协议。

use std::fmt;

use agentdeck_protocol::relay_v2::{EnrollmentCode, MachineRouteId, RelayServerId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::v2::store::{
    MachineInventoryEntry, MachineInventoryPage, MachineReadback, PurgeReadback,
};

pub const ADMIN_PROTOCOL_VERSION: u16 = 1;
pub const MAX_ADMIN_LINE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest32(pub [u8; 32]);

impl fmt::Debug for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Digest32(<redacted>)")
    }
}

impl Serialize for Digest32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Digest32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(serde::de::Error::custom)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected a 32-byte digest"))?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminRequest {
    MachineEnrollCreate {},
    MachineInventory {
        #[serde(default)]
        after: Option<MachineRouteId>,
    },
    MachineReadback {
        machine_route: MachineRouteId,
        confirm_root_fingerprint: Digest32,
    },
    MachinePurge {
        machine_route: MachineRouteId,
        confirm_root_fingerprint: Digest32,
    },
}

impl fmt::Debug for AdminRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let command = match self {
            Self::MachineEnrollCreate {} => "machine_enroll_create",
            Self::MachineInventory { .. } => "machine_inventory",
            Self::MachineReadback { .. } => "machine_readback",
            Self::MachinePurge { .. } => "machine_purge",
        };
        formatter
            .debug_struct("AdminRequest")
            .field("command", &command)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminResponse {
    Ok { result: AdminResult },
    Error { error: AdminFailure },
}

impl fmt::Debug for AdminResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok { result } => formatter
                .debug_struct("AdminResponse")
                .field("status", &"ok")
                .field("result", result)
                .finish(),
            Self::Error { error } => formatter
                .debug_struct("AdminResponse")
                .field("status", &"error")
                .field("code", &error.code)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminResult {
    EnrollmentBundle { bundle: EnrollmentBundleV1 },
    MachineInventory { page: MachineInventoryResult },
    MachineReadback { readback: MachineReadbackResult },
    MachinePurged { readback: PurgeReadbackResult },
}

impl fmt::Debug for AdminResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::EnrollmentBundle { .. } => "enrollment_bundle",
            Self::MachineInventory { .. } => "machine_inventory",
            Self::MachineReadback { .. } => "machine_readback",
            Self::MachinePurged { .. } => "machine_purged",
        };
        formatter
            .debug_struct("AdminResult")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminFailure {
    pub code: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentBundleV1 {
    pub version: u16,
    pub public_wss_url: String,
    pub relay_server_id: RelayServerId,
    pub code: EnrollmentCode,
    pub spki_pins: Vec<Digest32>,
    pub expires_at_ms: u64,
}

impl fmt::Debug for EnrollmentBundleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentBundleV1")
            .field("version", &self.version)
            .field("relay_server_id", &self.relay_server_id.redacted())
            .field("secret_material", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineInventoryResult {
    pub entries: Vec<MachineInventoryResultEntry>,
    pub next_after: Option<MachineRouteId>,
}

impl fmt::Debug for MachineInventoryResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineInventoryResult")
            .field("entry_count", &self.entries.len())
            .field("has_next", &self.next_after.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineInventoryResultEntry {
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub root_fingerprint: Digest32,
    pub trust_epoch: u64,
    pub retired: bool,
}

impl fmt::Debug for MachineInventoryResultEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineInventoryResultEntry")
            .field("relay_server", &self.relay_server_id.redacted())
            .field("machine", &self.machine_route.redacted())
            .field("root_fingerprint", &"<redacted>")
            .field("trust_epoch", &self.trust_epoch)
            .field("retired", &self.retired)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineReadbackResult {
    pub machine: MachineInventoryResultEntry,
    pub data: PurgeReadbackResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PurgeReadbackResult {
    pub active_machine_routes: u64,
    pub retired_tombstones: u64,
    pub device_grants: u64,
    pub revocations: u64,
    pub streams: u64,
    pub frames: u64,
    pub subscriptions: u64,
    pub retirement_hash: Option<Digest32>,
    pub retirement_terminal_present: bool,
}

impl From<MachineInventoryEntry> for MachineInventoryResultEntry {
    fn from(value: MachineInventoryEntry) -> Self {
        Self {
            relay_server_id: value.relay_server_id,
            machine_route: value.machine_route,
            root_fingerprint: Digest32(value.root_fingerprint),
            trust_epoch: value.trust_epoch.value(),
            retired: value.retired,
        }
    }
}

impl From<MachineInventoryPage> for MachineInventoryResult {
    fn from(value: MachineInventoryPage) -> Self {
        Self {
            entries: value.entries.into_iter().map(Into::into).collect(),
            next_after: value.next_after,
        }
    }
}

impl From<PurgeReadback> for PurgeReadbackResult {
    fn from(value: PurgeReadback) -> Self {
        Self {
            active_machine_routes: value.active_machine_routes,
            retired_tombstones: value.retired_tombstones,
            device_grants: value.device_grants,
            revocations: value.revocations,
            streams: value.streams,
            frames: value.frames,
            subscriptions: value.subscriptions,
            retirement_hash: value.retirement_hash.map(Digest32),
            retirement_terminal_present: value.retirement_terminal_blob.is_some(),
        }
    }
}

impl From<MachineReadback> for MachineReadbackResult {
    fn from(value: MachineReadback) -> Self {
        Self {
            machine: value.machine.into(),
            data: value.data.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_rejects_unknown_fields_and_debug_redacts_confirmation() {
        let route = MachineRouteId::from_bytes([1; 16]);
        let request = AdminRequest::MachinePurge {
            machine_route: route,
            confirm_root_fingerprint: Digest32([0x5a; 32]),
        };
        let encoded = serde_json::to_vec(&request).expect("encode request");
        let debug = format!("{request:?}");
        let route_wire = serde_json::to_string(&route).expect("encode route");
        assert!(!debug.contains("Wlpa"));
        assert!(!debug.contains(route_wire.trim_matches('"')));
        assert!(
            serde_json::from_slice::<AdminRequest>(
                br#"{"command":"machine_enroll_create","extra":true}"#,
            )
            .is_err()
        );
        let decoded: AdminRequest = serde_json::from_slice(&encoded).expect("decode request");
        assert_eq!(decoded, request);
    }

    #[test]
    fn digest_requires_exact_urlsafe_base64_without_padding() {
        let encoded = serde_json::to_string(&Digest32([7; 32])).expect("encode digest");
        assert!(!encoded.contains('='));
        assert!(serde_json::from_str::<Digest32>(r#""AA""#).is_err());
    }

    #[test]
    fn inventory_debug_redacts_route_and_fingerprint() {
        let route = MachineRouteId::from_bytes([0x5a; 16]);
        let entry = MachineInventoryResultEntry {
            relay_server_id: RelayServerId::from_bytes([0x6b; 16]),
            machine_route: route,
            root_fingerprint: Digest32([0x7c; 32]),
            trust_epoch: 1,
            retired: false,
        };
        let route_wire = serde_json::to_string(&route).expect("route wire");
        let fingerprint_wire =
            serde_json::to_string(&entry.root_fingerprint).expect("fingerprint wire");
        let debug = format!("{entry:?}");
        assert!(!debug.contains(route_wire.trim_matches('"')));
        assert!(!debug.contains(fingerprint_wire.trim_matches('"')));
    }
}
