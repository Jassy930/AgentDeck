// agentdeck-protocol/src/remote/data.rs
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// 数据面 payload：relay 不可见。R0 携带明文字节（内层 ClientCommand /
/// ServerEvent / HistoryResponse 的序列化 JSON）；R1/R2 追加 `Encrypted`
/// 变体，控制面与路由器零改动。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "seal", rename_all = "camelCase", deny_unknown_fields)]
pub enum DataEnvelope {
    Plaintext {
        #[serde(rename = "agentdeckProtocolVersion")]
        agentdeck_protocol_version: u32,
        bytes: Vec<u8>,
    },
    // Encrypted { alg, nonce, ciphertext, tag }  // R1/R2
}

impl DataEnvelope {
    /// 把可序列化的内层 payload 包成明文字节。
    pub fn plaintext<T: Serialize>(value: &T) -> Result<Self, serde_json::Error> {
        Ok(DataEnvelope::Plaintext {
            agentdeck_protocol_version: crate::PROTOCOL_VERSION,
            bytes: serde_json::to_vec(value)?,
        })
    }

    /// 解出内层 payload（仅接收端使用）。
    pub fn decode_plaintext<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        match self {
            DataEnvelope::Plaintext { bytes, .. } => serde_json::from_slice(bytes),
        }
    }
}
