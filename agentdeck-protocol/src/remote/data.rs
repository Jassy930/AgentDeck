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
        #[serde(with = "b64")]
        #[schemars(with = "String")]
        bytes: Vec<u8>,
    },
    // Encrypted { alg, nonce, ciphertext, tag }  // R1/R2
}

/// `bytes` 的 wire 编码：base64 字符串（而非 serde_json 默认的 uint8 数组），
/// 降低 WS 线上体积；schema 侧用 `#[schemars(with = "String")]` 保持一致。
mod b64 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plaintext_bytes_serialize_as_base64_string() {
        let env = DataEnvelope::Plaintext {
            agentdeck_protocol_version: 2,
            bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let v = serde_json::to_value(&env).unwrap();
        // bytes 必须是 base64 字符串，不是 JSON 数字数组
        assert_eq!(v["bytes"], serde_json::json!("3q2+7w=="));
        let back: DataEnvelope = serde_json::from_value(v).unwrap();
        assert_eq!(back, env);
    }
}
