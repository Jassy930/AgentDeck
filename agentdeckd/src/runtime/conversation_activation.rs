//! RuntimeCore 到 daemon-private key-transition owner 的中立接缝。
//!
//! Store 已把 conversation、publication mapping、ConversationDEK 与 transition
//! 原子提交后，Core 只要求 owner 把 durable transition 推进到 business-ready；
//! 本层不认识 Relay、crypto、Keychain 或 remote manager 类型。

use async_trait::async_trait;

const CONVERSATION_ACTIVATION_UNAVAILABLE: &str =
    "daemon.remote.conversation_activation.unavailable";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationActivationError {
    code: String,
}

impl ConversationActivationError {
    #[must_use]
    pub fn new(code: impl AsRef<str>) -> Self {
        let code = code.as_ref();
        let valid = !code.is_empty()
            && code.len() <= 128
            && code.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            });
        Self {
            code: if valid {
                code.to_owned()
            } else {
                CONVERSATION_ACTIVATION_UNAVAILABLE.to_owned()
            },
        }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

#[async_trait]
pub trait ConversationActivationCoordinator: Send + Sync {
    async fn drive_to_business_ready(&self) -> Result<(), ConversationActivationError>;
}

#[derive(Debug, Default)]
pub struct DisabledConversationActivationCoordinator;

#[async_trait]
impl ConversationActivationCoordinator for DisabledConversationActivationCoordinator {
    async fn drive_to_business_ready(&self) -> Result<(), ConversationActivationError> {
        Err(ConversationActivationError::new(
            CONVERSATION_ACTIVATION_UNAVAILABLE,
        ))
    }
}
