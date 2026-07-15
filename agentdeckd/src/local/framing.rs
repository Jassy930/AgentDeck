//! local Runtime v1 JSONL framing 与首帧判定。
//!
//! 威胁场景：未认证客户端可发送超长、重复字段或版本不兼容的 JSON，诱发无界内存、
//! 请求歧义，或让 daemon 在无法解释消息体时静默断线；本层先做有界读取与严格顶层
//! 探测，只在能可信关联原 `messageId` 时返回类型化失败。

use std::io;

use agentdeck_protocol::runtime::failure::{
    DAEMON_RUNTIME_INVALID_REQUEST, DAEMON_RUNTIME_PROTOCOL_MISMATCH,
};
use agentdeck_protocol::runtime::identity::MessageId;
use agentdeck_protocol::runtime::{
    MAX_RUNTIME_JSON_FRAME_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeFailure,
    RuntimeMessage, RuntimeReply, RuntimeRequest,
};
use serde::Deserialize;
use serde_json::value::RawValue;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use uuid::Uuid;

pub(crate) const LOCAL_PROTOCOL_VERSION: u16 = 1;
/// preface JSON payload 的最大字节数（不含结尾 LF）。
pub(crate) const MAX_LOCAL_PREFACE_JSON_BYTES: usize = 4095;
/// preface 整行最大字节数（含结尾 LF）。
pub(crate) const MAX_LOCAL_PREFACE_LINE_BYTES: usize = 4096;

/// 已严格解析的 local-only client preface。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LocalClientPrefaceV1 {
    client_installation_id: [u8; 16],
}

impl LocalClientPrefaceV1 {
    /// 解析不含结尾 LF 的 preface JSON payload。
    pub(crate) fn decode(frame: &[u8]) -> Result<Self, LocalPrefaceError> {
        if frame.len() > MAX_LOCAL_PREFACE_JSON_BYTES {
            return Err(LocalPrefaceError::TooLarge);
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            local_protocol_version: u16,
            client_installation_id: String,
        }

        let wire: Wire = serde_json::from_slice(frame).map_err(LocalPrefaceError::InvalidJson)?;
        if wire.local_protocol_version != LOCAL_PROTOCOL_VERSION {
            return Err(LocalPrefaceError::UnsupportedVersion {
                received: wire.local_protocol_version,
            });
        }

        let uuid = Uuid::parse_str(&wire.client_installation_id)
            .map_err(|_| LocalPrefaceError::InvalidClientInstallationId)?;
        if uuid.is_nil() || uuid.hyphenated().to_string() != wire.client_installation_id {
            return Err(LocalPrefaceError::InvalidClientInstallationId);
        }

        Ok(Self {
            client_installation_id: *uuid.as_bytes(),
        })
    }

    pub(crate) fn client_installation_id(self) -> [u8; 16] {
        self.client_installation_id
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LocalPrefaceError {
    #[error("local client preface exceeds 4095 JSON bytes")]
    TooLarge,
    #[error("invalid local client preface JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),
    #[error("unsupported local protocol version {received}")]
    UnsupportedVersion { received: u16 },
    #[error("clientInstallationId must be a canonical lowercase non-nil UUID")]
    InvalidClientInstallationId,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum JsonlReadError {
    #[error("JSONL frame limit must be non-zero")]
    InvalidLimit,
    #[error("JSONL frame reached the exclusive {exclusive_cap}-byte cap")]
    TooLarge { exclusive_cap: usize },
    #[error("JSONL stream ended before LF terminator")]
    Unterminated,
    #[error("failed to read JSONL frame: {0}")]
    Io(#[source] io::Error),
}

/// 读取一条不含 LF 的 raw JSONL frame；payload 必须严格小于 `exclusive_cap`。
///
/// 空流返回 `Ok(None)`；已经读到部分 payload 后 EOF 属于 malformed frame。达到（包括
/// 刚好达到）cap 时立即拒绝，避免为攻击者输入继续扩容。
pub(crate) async fn read_jsonl_frame<R>(
    reader: &mut R,
    exclusive_cap: usize,
) -> Result<Option<Vec<u8>>, JsonlReadError>
where
    R: AsyncBufRead + Unpin + ?Sized,
{
    if exclusive_cap == 0 {
        return Err(JsonlReadError::InvalidLimit);
    }

    let mut frame = Vec::with_capacity(exclusive_cap.min(8192));
    loop {
        let available = reader.fill_buf().await.map_err(JsonlReadError::Io)?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(JsonlReadError::Unterminated)
            };
        }

        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            let frame_len = frame
                .len()
                .checked_add(newline)
                .ok_or(JsonlReadError::TooLarge { exclusive_cap })?;
            if frame_len >= exclusive_cap {
                return Err(JsonlReadError::TooLarge { exclusive_cap });
            }
            frame.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            return Ok(Some(frame));
        }

        let available_len = available.len();
        let frame_len = frame
            .len()
            .checked_add(available_len)
            .ok_or(JsonlReadError::TooLarge { exclusive_cap })?;
        if frame_len >= exclusive_cap {
            return Err(JsonlReadError::TooLarge { exclusive_cap });
        }
        frame.extend_from_slice(available);
        reader.consume(available_len);
    }
}

/// 不做 typed body 解码的严格 Runtime 顶层探测结果。
///
/// `raw_body` 保留为未类型化 JSON；这允许错误版本在不解释其具体请求结构的情况下
/// 仍返回同 `messageId` 的 protocol mismatch。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeFrameHeader<'frame> {
    pub(crate) version: u16,
    pub(crate) message_id: MessageId,
    #[serde(borrow, rename = "body")]
    pub(crate) raw_body: &'frame RawValue,
}

pub(crate) fn probe_runtime_header(
    frame: &[u8],
) -> Result<RuntimeFrameHeader<'_>, serde_json::Error> {
    serde_json::from_slice(frame)
}

/// local reader 对一条 Runtime frame 的无歧义处理决策。
#[derive(Debug)]
pub(crate) enum RuntimeFrameDecision {
    /// 完整 Runtime v1 envelope，可交给 Core。
    Accept(RuntimeEnvelope),
    /// 写出类型化回复、flush 后关闭当前连接。
    ReplyThenClose(RuntimeEnvelope),
    /// 不具备可信回复关联信息，直接关闭当前连接。
    Close,
}

/// 顶层探测后完整解码 Runtime v1；错误版本返回同 messageId 的类型化失败。
pub(crate) fn decode_runtime_frame(frame: &[u8]) -> RuntimeFrameDecision {
    if frame.len() >= MAX_RUNTIME_JSON_FRAME_BYTES {
        return RuntimeFrameDecision::Close;
    }

    let header = match probe_runtime_header(frame) {
        Ok(header) => header,
        Err(_) => return RuntimeFrameDecision::Close,
    };
    let RuntimeFrameHeader {
        version,
        message_id,
        raw_body,
    } = header;
    // header probe 必须完整消费 body 才能确认整条 JSON 合法；RawValue 只借用原 frame，
    // typed decode 仍从原 bytes 开始，不构造未知版本的 JSON 树或改写 wire 语义。
    let _ = raw_body;
    if version != RUNTIME_PROTOCOL_VERSION {
        return reply_then_close(
            message_id,
            DAEMON_RUNTIME_PROTOCOL_MISMATCH,
            "runtime protocol version is incompatible",
        );
    }

    match serde_json::from_slice(frame) {
        Ok(envelope) => RuntimeFrameDecision::Accept(envelope),
        Err(_) => RuntimeFrameDecision::Close,
    }
}

/// 解码连接首条 Runtime frame，并强制它是 `Request::Hello`。
pub(crate) fn decode_first_runtime_frame(frame: &[u8]) -> RuntimeFrameDecision {
    match decode_runtime_frame(frame) {
        RuntimeFrameDecision::Accept(envelope)
            if matches!(
                &envelope.body,
                RuntimeMessage::Request(RuntimeRequest::Hello(_))
            ) =>
        {
            RuntimeFrameDecision::Accept(envelope)
        }
        RuntimeFrameDecision::Accept(envelope) => reply_then_close(
            envelope.message_id,
            DAEMON_RUNTIME_INVALID_REQUEST,
            "first runtime frame must be Request::Hello",
        ),
        decision => decision,
    }
}

fn reply_then_close(
    message_id: MessageId,
    code: &'static str,
    message: &'static str,
) -> RuntimeFrameDecision {
    RuntimeFrameDecision::ReplyThenClose(RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id,
        body: RuntimeMessage::Reply(RuntimeReply::Failure(RuntimeFailure::new(code, message))),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use agentdeck_protocol::runtime::command::HelloParams;
    use agentdeck_protocol::runtime::failure::{
        DAEMON_RUNTIME_INVALID_REQUEST, DAEMON_RUNTIME_PROTOCOL_MISMATCH,
    };
    use agentdeck_protocol::runtime::{
        MAX_RUNTIME_JSON_FRAME_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeMessage, RuntimeReply,
        RuntimeRequest,
    };
    use serde_json::json;
    use tokio::io::BufReader;
    use uuid::Uuid;

    use super::{
        JsonlReadError, LOCAL_PROTOCOL_VERSION, LocalClientPrefaceV1, LocalPrefaceError,
        MAX_LOCAL_PREFACE_JSON_BYTES, MAX_LOCAL_PREFACE_LINE_BYTES, RuntimeFrameDecision,
        decode_first_runtime_frame, decode_runtime_frame, probe_runtime_header, read_jsonl_frame,
    };

    const INSTALLATION_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn valid_preface() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "localProtocolVersion": LOCAL_PROTOCOL_VERSION,
            "clientInstallationId": INSTALLATION_ID,
        }))
        .expect("preface fixture")
    }

    fn hello_frame(version: u16, message_id: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": version,
            "messageId": message_id,
            "body": {
                "message": "request",
                "payload": {
                    "request": "hello",
                    "runtimeProtocolVersion": RUNTIME_PROTOCOL_VERSION,
                },
            },
        }))
        .expect("hello fixture")
    }

    fn failure_code(decision: RuntimeFrameDecision) -> (u16, &'static str, String) {
        let RuntimeFrameDecision::ReplyThenClose(envelope) = decision else {
            panic!("expected reply then close");
        };
        let RuntimeMessage::Reply(RuntimeReply::Failure(failure)) = envelope.body else {
            panic!("expected typed failure");
        };
        let known_code = match failure.code.as_str() {
            DAEMON_RUNTIME_PROTOCOL_MISMATCH => DAEMON_RUNTIME_PROTOCOL_MISMATCH,
            DAEMON_RUNTIME_INVALID_REQUEST => DAEMON_RUNTIME_INVALID_REQUEST,
            other => panic!("unexpected failure code {other}"),
        };
        (
            envelope.version,
            known_code,
            envelope.message_id.as_str().to_owned(),
        )
    }

    #[test]
    fn strict_preface_accepts_canonical_lowercase_non_nil_uuid() {
        let preface = LocalClientPrefaceV1::decode(&valid_preface()).expect("valid preface");

        assert_eq!(
            Uuid::from_bytes(preface.client_installation_id()).to_string(),
            INSTALLATION_ID
        );
    }

    #[test]
    fn strict_preface_rejects_wrong_version() {
        let frame = serde_json::to_vec(&json!({
            "localProtocolVersion": LOCAL_PROTOCOL_VERSION + 1,
            "clientInstallationId": INSTALLATION_ID,
        }))
        .unwrap();

        assert!(matches!(
            LocalClientPrefaceV1::decode(&frame),
            Err(LocalPrefaceError::UnsupportedVersion { received: 2 })
        ));
    }

    #[test]
    fn strict_preface_rejects_noncanonical_or_nil_uuid() {
        for invalid in [
            "123E4567-E89B-12D3-A456-426614174000",
            "123e4567e89b12d3a456426614174000",
            "00000000-0000-0000-0000-000000000000",
            "not-a-uuid",
        ] {
            let frame = serde_json::to_vec(&json!({
                "localProtocolVersion": LOCAL_PROTOCOL_VERSION,
                "clientInstallationId": invalid,
            }))
            .unwrap();
            assert!(matches!(
                LocalClientPrefaceV1::decode(&frame),
                Err(LocalPrefaceError::InvalidClientInstallationId)
            ));
        }
    }

    #[test]
    fn strict_preface_rejects_missing_unknown_and_duplicate_fields() {
        let invalid_frames = [
            format!(
                r#"{{"localProtocolVersion":1,"clientInstallationId":"{INSTALLATION_ID}","extra":true}}"#
            ),
            r#"{"localProtocolVersion":1}"#.to_owned(),
            format!(
                r#"{{"localProtocolVersion":1,"localProtocolVersion":1,"clientInstallationId":"{INSTALLATION_ID}"}}"#
            ),
            format!(
                r#"{{"localProtocolVersion":1,"clientInstallationId":"{INSTALLATION_ID}","clientInstallationId":"{INSTALLATION_ID}"}}"#
            ),
        ];

        for frame in invalid_frames {
            assert!(matches!(
                LocalClientPrefaceV1::decode(frame.as_bytes()),
                Err(LocalPrefaceError::InvalidJson(_))
            ));
        }
    }

    #[test]
    fn preface_accepts_4095_json_bytes_and_rejects_4096() {
        let mut max = valid_preface();
        max.resize(MAX_LOCAL_PREFACE_JSON_BYTES, b' ');
        assert_eq!(max.len(), 4095);
        LocalClientPrefaceV1::decode(&max).expect("4095-byte JSON payload");

        max.push(b' ');
        assert!(matches!(
            LocalClientPrefaceV1::decode(&max),
            Err(LocalPrefaceError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn bounded_jsonl_accepts_cap_minus_one_and_consumes_lf() {
        let mut wire = vec![b'x'; MAX_LOCAL_PREFACE_JSON_BYTES];
        wire.push(b'\n');
        wire.extend_from_slice(b"next\n");
        let mut reader = BufReader::with_capacity(127, Cursor::new(wire));

        let frame = read_jsonl_frame(&mut reader, MAX_LOCAL_PREFACE_LINE_BYTES)
            .await
            .expect("bounded frame")
            .expect("one frame");
        let next = read_jsonl_frame(&mut reader, MAX_LOCAL_PREFACE_LINE_BYTES)
            .await
            .expect("next frame")
            .expect("one frame");

        assert_eq!(frame.len(), MAX_LOCAL_PREFACE_JSON_BYTES);
        assert_eq!(next, b"next");
    }

    #[tokio::test]
    async fn bounded_jsonl_rejects_exact_cap() {
        let mut wire = vec![b'x'; MAX_RUNTIME_JSON_FRAME_BYTES];
        wire.push(b'\n');
        let mut reader = BufReader::with_capacity(4096, Cursor::new(wire));

        let error = read_jsonl_frame(&mut reader, MAX_RUNTIME_JSON_FRAME_BYTES)
            .await
            .expect_err("exact cap must fail");

        assert!(matches!(
            error,
            JsonlReadError::TooLarge {
                exclusive_cap: 1_048_576
            }
        ));
    }

    #[tokio::test]
    async fn bounded_jsonl_distinguishes_clean_eof_from_partial_line() {
        let mut empty = BufReader::new(Cursor::new(Vec::<u8>::new()));
        assert!(
            read_jsonl_frame(&mut empty, 32)
                .await
                .expect("clean eof")
                .is_none()
        );

        let mut partial = BufReader::new(Cursor::new(b"{}".to_vec()));
        assert!(matches!(
            read_jsonl_frame(&mut partial, 32).await,
            Err(JsonlReadError::Unterminated)
        ));
    }

    #[test]
    fn header_probe_is_strict_but_keeps_body_untyped() {
        let frame = serde_json::to_vec(&json!({
            "version": 99,
            "messageId": "probe-1",
            "body": {"futureShape": [1, 2, 3]},
        }))
        .unwrap();

        let header = probe_runtime_header(&frame).expect("strict header");

        assert_eq!(header.version, 99);
        assert_eq!(header.message_id.as_str(), "probe-1");
        assert_eq!(header.raw_body.get(), r#"{"futureShape":[1,2,3]}"#);
        let body_start = header.raw_body.get().as_ptr() as usize;
        let frame_start = frame.as_ptr() as usize;
        assert!(
            (frame_start..frame_start + frame.len()).contains(&body_start),
            "raw body must borrow the bounded input frame"
        );
    }

    #[test]
    fn wrong_runtime_version_returns_same_message_id_protocol_mismatch() {
        let decision = decode_runtime_frame(&hello_frame(
            RUNTIME_PROTOCOL_VERSION + 1,
            "wrong-version-message",
        ));

        assert_eq!(
            failure_code(decision),
            (
                RUNTIME_PROTOCOL_VERSION,
                DAEMON_RUNTIME_PROTOCOL_MISMATCH,
                "wrong-version-message".to_owned()
            )
        );
    }

    #[test]
    fn malformed_duplicate_or_unknown_top_level_has_no_reply() {
        let invalid_frames = [
            br#"{"version":1,"messageId":"m","body":{}"#.as_slice(),
            br#"{"version":1,"version":1,"messageId":"m","body":{}}"#.as_slice(),
            br#"{"version":1,"messageId":"m","messageId":"m2","body":{}}"#.as_slice(),
            br#"{"version":1,"messageId":"m","body":{},"body":{}}"#.as_slice(),
            br#"{"version":1,"messageId":"m","body":{},"extra":true}"#.as_slice(),
        ];

        for frame in invalid_frames {
            assert!(matches!(
                decode_runtime_frame(frame),
                RuntimeFrameDecision::Close
            ));
        }
    }

    #[test]
    fn runtime_v1_performs_full_typed_envelope_decode() {
        let decision = decode_runtime_frame(&hello_frame(RUNTIME_PROTOCOL_VERSION, "hello-1"));

        let RuntimeFrameDecision::Accept(envelope) = decision else {
            panic!("valid v1 envelope must be accepted");
        };
        assert!(matches!(
            envelope.body,
            RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
            }))
        ));

        let invalid_typed_body =
            br#"{"version":1,"messageId":"bad-body","body":{"futureShape":true}}"#;
        assert!(matches!(
            decode_runtime_frame(invalid_typed_body),
            RuntimeFrameDecision::Close
        ));
    }

    #[test]
    fn first_frame_requires_request_hello_and_closes_with_invalid_request() {
        let non_hello = serde_json::to_vec(&json!({
            "version": RUNTIME_PROTOCOL_VERSION,
            "messageId": "not-hello",
            "body": {
                "message": "request",
                "payload": {
                    "request": "catalog",
                    "pageCursor": null,
                },
            },
        }))
        .unwrap();

        assert_eq!(
            failure_code(decode_first_runtime_frame(&non_hello)),
            (
                RUNTIME_PROTOCOL_VERSION,
                DAEMON_RUNTIME_INVALID_REQUEST,
                "not-hello".to_owned()
            )
        );
    }

    #[test]
    fn first_hello_inner_version_mismatch_is_left_for_core() {
        let inner_mismatch = serde_json::to_vec(&json!({
            "version": RUNTIME_PROTOCOL_VERSION,
            "messageId": "inner-mismatch",
            "body": {
                "message": "request",
                "payload": {
                    "request": "hello",
                    "runtimeProtocolVersion": RUNTIME_PROTOCOL_VERSION + 1,
                },
            },
        }))
        .unwrap();

        let RuntimeFrameDecision::Accept(envelope) = decode_first_runtime_frame(&inner_mismatch)
        else {
            panic!("inner version negotiation belongs to RuntimeCore");
        };
        assert!(matches!(
            envelope.body,
            RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
                runtime_protocol_version
            })) if runtime_protocol_version == RUNTIME_PROTOCOL_VERSION + 1
        ));
    }

    #[test]
    fn first_frame_accepts_request_hello() {
        assert!(matches!(
            decode_first_runtime_frame(&hello_frame(RUNTIME_PROTOCOL_VERSION, "hello-first")),
            RuntimeFrameDecision::Accept(_)
        ));
    }
}
