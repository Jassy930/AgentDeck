//! `claude auth status` probe + auth state types.
//!
//! Phase 4 Task 4B. Per K9 / N8, AgentDeck never reads, stores, or
//! forwards Claude credentials — this module only shells out to
//! `claude auth status` and surfaces a small enum derived from the
//! command's exit code + JSON output.
//!
//! ## Real wire shape (probed against `claude 2.1.191`)
//!
//! ```json
//! {
//!   "loggedIn": true,
//!   "authMethod": "oauth_token",
//!   "apiProvider": "firstParty"
//! }
//! ```
//!
//! - `authMethod ∈ {oauth_token, api_key, console, none, …}`
//! - `apiProvider ∈ {firstParty, bedrock, vertex, foundry, …}`
//! - Exit code: 0 when logged in, 1 when not authenticated, other on
//!   spawn / config failure.
//!
//! Spec § 5.7 had assumed an `account.type ∈ {subscription, console}`
//! object — the real shape uses flat `authMethod` / `apiProvider`
//! fields. The deserializer accepts both (legacy `account.type` if
//! present, plus the live fields) so a future CC shape change in
//! either direction lands soft.

use serde::Deserialize;

/// Tri+1 state surfaced to capabilities + diagnostics. Differentiates
/// the two common "logged in" sources because the UI distinguishes them
/// (subscription mini-panel vs. API-key indicator).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// Logged in via OAuth / subscription (claude.ai / Pro / Max).
    LoggedInSubscription,
    /// Logged in via Console API key or `ANTHROPIC_API_KEY` env.
    LoggedInConsoleApiKey,
    /// `claude auth status` returned exit 1 / explicit not-logged-in.
    NotAuthenticated,
    /// Spawn failed, JSON unparseable, or shape unrecognized. Treated
    /// as "best-effort unknown" — UI shows a neutral badge and the
    /// adapter does NOT block session start (CC may still work via env).
    Unknown,
}

/// CC's auth-status JSON shape. All fields optional so deserialization
/// survives shape drift; the classification function below decides
/// `AuthState` from whatever subset of fields the live CLI returns.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AuthStatusJson {
    #[serde(alias = "loggedIn", alias = "logged_in")]
    logged_in: bool,
    /// Live CLI field (`oauth_token` | `api_key` | `console` | `none`).
    #[serde(alias = "authMethod", alias = "auth_method")]
    auth_method: Option<String>,
    /// Live CLI field (`firstParty` | `bedrock` | `vertex` | `foundry`).
    #[serde(alias = "apiProvider", alias = "api_provider")]
    api_provider: Option<String>,
    /// Legacy / spec-anticipated shape: kept as a fallback if a future
    /// CC build switches back to a nested account block.
    account: Option<AccountBlock>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AccountBlock {
    #[serde(rename = "type")]
    type_: Option<String>,
}

/// Classify a parsed JSON payload into an `AuthState`. Pure function —
/// no I/O, easy to unit-test against recorded fixtures.
fn classify(json: &AuthStatusJson) -> AuthState {
    if !json.logged_in {
        return AuthState::NotAuthenticated;
    }
    // Prefer live fields, fall back to legacy `account.type`.
    let mut hint: Option<&str> = json.auth_method.as_deref();
    if hint.is_none() {
        hint = json.account.as_ref().and_then(|a| a.type_.as_deref());
    }
    match hint {
        Some("oauth_token") | Some("oauth") | Some("subscription") => {
            AuthState::LoggedInSubscription
        }
        Some("api_key") | Some("console") | Some("apiKey") => {
            AuthState::LoggedInConsoleApiKey
        }
        // `apiProvider != firstParty` strongly suggests an API-key
        // route even if `authMethod` is missing (e.g. `bedrock`).
        _ => match json.api_provider.as_deref() {
            Some(p) if p != "firstParty" && p != "first_party" => {
                AuthState::LoggedInConsoleApiKey
            }
            // Logged in, neither field told us — assume the most
            // common (subscription) but the UI may still show
            // "unknown" badge through this enum's degraded variants.
            _ => AuthState::LoggedInSubscription,
        },
    }
}

/// Test-injectable variant of `probe_auth_status`. Takes a closure that
/// returns the `(exit_code, stdout_text)` pair so tests can exercise
/// every branch without spawning `claude`.
pub fn probe_auth_status_with_command<F>(run: F) -> AuthState
where
    F: FnOnce() -> Result<(i32, String), String>,
{
    match run() {
        Err(_) => AuthState::Unknown,
        Ok((1, _)) => AuthState::NotAuthenticated,
        Ok((0, stdout)) => match serde_json::from_str::<AuthStatusJson>(stdout.trim()) {
            Ok(j) => classify(&j),
            Err(_) => AuthState::Unknown,
        },
        Ok(_) => AuthState::Unknown,
    }
}

/// Production probe. Runs `claude auth status` (sync) and returns the
/// classified state. Never panics; never reads, stores or forwards
/// the JSON payload beyond the deserialized fields (K9 守护).
pub fn probe_auth_status() -> AuthState {
    probe_auth_status_with_command(|| {
        use std::process::Command;
        match Command::new("claude").arg("auth").arg("status").output() {
            Ok(out) => Ok((
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stdout).to_string(),
            )),
            Err(e) => Err(e.to_string()),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_subscription_oauth_token() {
        // Real shape captured from `claude 2.1.191 auth status`.
        let stdout = r#"{"loggedIn":true,"authMethod":"oauth_token","apiProvider":"firstParty"}"#;
        let state = probe_auth_status_with_command(|| Ok((0, stdout.into())));
        assert_eq!(state, AuthState::LoggedInSubscription);
    }

    #[test]
    fn classify_console_api_key() {
        let stdout = r#"{"loggedIn":true,"authMethod":"api_key","apiProvider":"firstParty"}"#;
        let state = probe_auth_status_with_command(|| Ok((0, stdout.into())));
        assert_eq!(state, AuthState::LoggedInConsoleApiKey);
    }

    #[test]
    fn classify_bedrock_provider_as_api_key() {
        // Logged in via Bedrock — no oauth involved, classify as API
        // key route even when `authMethod` is absent.
        let stdout = r#"{"loggedIn":true,"apiProvider":"bedrock"}"#;
        let state = probe_auth_status_with_command(|| Ok((0, stdout.into())));
        assert_eq!(state, AuthState::LoggedInConsoleApiKey);
    }

    #[test]
    fn classify_legacy_account_subscription_shape() {
        // Defensive: if a future CC build switches back to the
        // anticipated `account.type` shape, we still classify.
        let stdout = r#"{"loggedIn":true,"account":{"type":"subscription"}}"#;
        let state = probe_auth_status_with_command(|| Ok((0, stdout.into())));
        assert_eq!(state, AuthState::LoggedInSubscription);
    }

    #[test]
    fn classify_not_authenticated_exit_1() {
        let state = probe_auth_status_with_command(|| Ok((1, "".into())));
        assert_eq!(state, AuthState::NotAuthenticated);
    }

    #[test]
    fn classify_not_authenticated_exit_0_logged_out_json() {
        let state = probe_auth_status_with_command(|| Ok((0, r#"{"loggedIn":false}"#.into())));
        assert_eq!(state, AuthState::NotAuthenticated);
    }

    #[test]
    fn classify_unknown_on_spawn_error() {
        let state = probe_auth_status_with_command(|| Err("no such file".into()));
        assert_eq!(state, AuthState::Unknown);
    }

    #[test]
    fn classify_unknown_on_malformed_json() {
        let state = probe_auth_status_with_command(|| Ok((0, "not-json".into())));
        assert_eq!(state, AuthState::Unknown);
    }
}
