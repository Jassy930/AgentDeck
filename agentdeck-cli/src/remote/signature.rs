//! Persistent remote CLI 的 production code-signing gate。
//!
//! production expectation 只能由编译期值建立；运行时环境、CLI 参数或配置文件均不能
//! 替换 identifier、TeamIdentifier 或 Keychain access group。automatic harness 可以注入
//! verifier，但只有通过同一 exact policy 才能取得 [`VerifiedRemoteCliIdentity`] capability。

use std::fmt;
use std::io;

use thiserror::Error;

/// release CLI 固定的 Mach-O code identifier。
pub const REMOTE_CLI_CODE_IDENTIFIER: &str = "com.agentdeck.agentdeck-cli";
/// release CLI 独占、不得与 App/daemon 共享的 Keychain access-group suffix。
pub const REMOTE_CLI_ACCESS_GROUP_SUFFIX: &str = ".com.agentdeck.remote.cli";

#[cfg(target_os = "macos")]
const MAX_VERIFIER_OUTPUT_BYTES: usize = 256 * 1024;
#[cfg(target_os = "macos")]
const VERIFIER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(target_os = "macos")]
const VERIFIER_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);
#[cfg(target_os = "macos")]
const VERIFIER_PIPE_CHUNK_BYTES: usize = 8 * 1024;

/// 编译期冻结的 release CLI identity expectation。
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteCliSignatureExpectation {
    code_identifier: String,
    team_identifier: String,
    keychain_access_group: String,
}

impl fmt::Debug for RemoteCliSignatureExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteCliSignatureExpectation([REDACTED])")
    }
}

impl RemoteCliSignatureExpectation {
    /// 只读取构建流水线在编译时注入的 identity；运行时同名环境变量不会生效。
    pub fn compiled() -> Result<Self, RemoteCliSignatureError> {
        let code_identifier = option_env!("AGENTDECK_CLI_CODE_IDENTIFIER").ok_or(
            RemoteCliSignatureError::ProductionIdentityUnavailable {
                field: "code identifier",
            },
        )?;
        let team_identifier = option_env!("AGENTDECK_CLI_TEAM_IDENTIFIER").ok_or(
            RemoteCliSignatureError::ProductionIdentityUnavailable {
                field: "TeamIdentifier",
            },
        )?;
        let keychain_access_group = option_env!("AGENTDECK_CLI_KEYCHAIN_ACCESS_GROUP").ok_or(
            RemoteCliSignatureError::ProductionIdentityUnavailable {
                field: "Keychain access group",
            },
        )?;
        Self::new(code_identifier, team_identifier, keychain_access_group)
    }

    /// Library automatic tests 的 expectation constructor；production binary 不从输入构造它。
    #[doc(hidden)]
    pub fn for_test(
        code_identifier: impl Into<String>,
        team_identifier: impl Into<String>,
        keychain_access_group: impl Into<String>,
    ) -> Result<Self, RemoteCliSignatureError> {
        Self::new(code_identifier, team_identifier, keychain_access_group)
    }

    fn new(
        code_identifier: impl Into<String>,
        team_identifier: impl Into<String>,
        keychain_access_group: impl Into<String>,
    ) -> Result<Self, RemoteCliSignatureError> {
        let code_identifier = code_identifier.into();
        let team_identifier = team_identifier.into();
        let keychain_access_group = keychain_access_group.into();
        if code_identifier != REMOTE_CLI_CODE_IDENTIFIER {
            return Err(RemoteCliSignatureError::InvalidExpectation {
                field: "code identifier",
            });
        }
        if !valid_team_identifier(&team_identifier) {
            return Err(RemoteCliSignatureError::InvalidExpectation {
                field: "TeamIdentifier",
            });
        }
        let required_group = format!("{team_identifier}{REMOTE_CLI_ACCESS_GROUP_SUFFIX}");
        if keychain_access_group != required_group {
            return Err(RemoteCliSignatureError::InvalidExpectation {
                field: "Keychain access group",
            });
        }
        Ok(Self {
            code_identifier,
            team_identifier,
            keychain_access_group,
        })
    }

    #[must_use]
    pub fn code_identifier(&self) -> &str {
        &self.code_identifier
    }

    #[must_use]
    pub fn team_identifier(&self) -> &str {
        &self.team_identifier
    }

    #[must_use]
    pub fn keychain_access_group(&self) -> &str {
        &self.keychain_access_group
    }

    #[cfg(target_os = "macos")]
    fn designated_requirement(&self) -> String {
        format!(
            "anchor apple generic and identifier \"{}\" and certificate leaf[subject.OU] = \"{}\"",
            self.code_identifier, self.team_identifier
        )
    }
}

/// verifier 观察到的签名类别。只有 `Production` 能生成 verified capability。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteCliSignatureKind {
    Production,
    AdHoc,
    Unsigned,
}

/// 可注入 verifier 的完整观察值；调用方不能据此绕过 exact policy。
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteCliSignatureAttestation {
    signature: RemoteCliSignatureKind,
    code_identifier: String,
    team_identifier: String,
    keychain_access_groups: Vec<String>,
}

impl fmt::Debug for RemoteCliSignatureAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteCliSignatureAttestation([REDACTED])")
    }
}

impl RemoteCliSignatureAttestation {
    #[must_use]
    pub fn new(
        signature: RemoteCliSignatureKind,
        code_identifier: impl Into<String>,
        team_identifier: impl Into<String>,
        keychain_access_groups: Vec<String>,
    ) -> Self {
        Self {
            signature,
            code_identifier: code_identifier.into(),
            team_identifier: team_identifier.into(),
            keychain_access_groups,
        }
    }
}

/// current executable code identity 的可注入只读边界。
pub trait CurrentRemoteCliSignatureVerifier: Send + Sync {
    fn verify_current(
        &self,
        expected: &RemoteCliSignatureExpectation,
    ) -> Result<RemoteCliSignatureAttestation, RemoteCliSignatureError>;
}

/// exact policy 验证后的不可伪造 type-state；字段私有，不能由 adapter 自行构造。
///
/// ```compile_fail
/// use agentdeck_cli::remote::signature::VerifiedRemoteCliIdentity;
/// let _ = VerifiedRemoteCliIdentity {
///     code_identifier: String::new(),
///     team_identifier: String::new(),
///     keychain_access_group: String::new(),
/// };
/// ```
pub struct VerifiedRemoteCliIdentity {
    code_identifier: String,
    team_identifier: String,
    keychain_access_group: String,
}

impl fmt::Debug for VerifiedRemoteCliIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedRemoteCliIdentity([REDACTED])")
    }
}

impl VerifiedRemoteCliIdentity {
    #[must_use]
    pub fn code_identifier(&self) -> &str {
        &self.code_identifier
    }

    #[must_use]
    pub fn team_identifier(&self) -> &str {
        &self.team_identifier
    }

    #[must_use]
    pub fn keychain_access_group(&self) -> &str {
        &self.keychain_access_group
    }
}

/// 运行 verifier 并在任何后续 Keychain/state/network mutation 前收窄为 verified type-state。
pub fn verify_current_remote_cli_identity<V: CurrentRemoteCliSignatureVerifier + ?Sized>(
    expected: &RemoteCliSignatureExpectation,
    verifier: &V,
) -> Result<VerifiedRemoteCliIdentity, RemoteCliSignatureError> {
    let observed = verifier.verify_current(expected)?;
    match observed.signature {
        RemoteCliSignatureKind::Unsigned => {
            return Err(RemoteCliSignatureError::UnsignedSignature);
        }
        RemoteCliSignatureKind::AdHoc => return Err(RemoteCliSignatureError::AdHocSignature),
        RemoteCliSignatureKind::Production => {}
    }
    if observed.code_identifier != expected.code_identifier {
        return Err(RemoteCliSignatureError::CodeIdentifierMismatch);
    }
    if observed.team_identifier != expected.team_identifier {
        return Err(RemoteCliSignatureError::TeamIdentifierMismatch);
    }
    if observed.keychain_access_groups.as_slice() != [expected.keychain_access_group.as_str()] {
        return Err(RemoteCliSignatureError::AccessGroupMismatch);
    }
    Ok(VerifiedRemoteCliIdentity {
        code_identifier: expected.code_identifier.clone(),
        team_identifier: expected.team_identifier.clone(),
        keychain_access_group: expected.keychain_access_group.clone(),
    })
}

/// `/usr/bin/codesign` + `/usr/bin/plutil` 的 bounded production verifier。
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionRemoteCliSignatureVerifier;

impl ProductionRemoteCliSignatureVerifier {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CurrentRemoteCliSignatureVerifier for ProductionRemoteCliSignatureVerifier {
    fn verify_current(
        &self,
        expected: &RemoteCliSignatureExpectation,
    ) -> Result<RemoteCliSignatureAttestation, RemoteCliSignatureError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = expected;
            Err(RemoteCliSignatureError::UnsupportedPlatform)
        }
        #[cfg(target_os = "macos")]
        {
            verify_current_macos_cli(expected)
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RemoteCliSignatureError {
    #[error("persistent remote CLI is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("production remote CLI identity is not compiled in: {field}")]
    ProductionIdentityUnavailable { field: &'static str },
    #[error("invalid production remote CLI expectation: {field}")]
    InvalidExpectation { field: &'static str },
    #[error("current remote CLI is unsigned")]
    UnsignedSignature,
    #[error("current remote CLI uses a forbidden ad-hoc signature")]
    AdHocSignature,
    #[error("current remote CLI does not satisfy the designated requirement")]
    SignatureRejected,
    #[error("current remote CLI code identifier does not match the compiled expectation")]
    CodeIdentifierMismatch,
    #[error("current remote CLI TeamIdentifier does not match the compiled expectation")]
    TeamIdentifierMismatch,
    #[error("current remote CLI Keychain access group is not the exact singleton expectation")]
    AccessGroupMismatch,
    #[error("current remote CLI entitlement is missing or malformed: {field}")]
    InvalidVerifierOutput { field: &'static str },
    #[error("{operation} timed out")]
    VerifierTimedOut { operation: &'static str },
    #[error("{operation} output exceeded the fixed bound")]
    VerifierOutputTooLarge { operation: &'static str },
    #[error("{operation} failed with I/O kind {kind:?} and errno {raw_os_error:?}")]
    VerifierIo {
        operation: &'static str,
        kind: io::ErrorKind,
        raw_os_error: Option<i32>,
    },
}

impl RemoteCliSignatureError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform | Self::ProductionIdentityUnavailable { .. } => {
                "remote.persistent.unsupported"
            }
            Self::InvalidExpectation { .. } => "remote.persistent.expectation_invalid",
            Self::UnsignedSignature | Self::AdHocSignature | Self::SignatureRejected => {
                "remote.persistent.signature_invalid"
            }
            Self::CodeIdentifierMismatch
            | Self::TeamIdentifierMismatch
            | Self::AccessGroupMismatch
            | Self::InvalidVerifierOutput { .. } => "remote.persistent.identity_invalid",
            Self::VerifierTimedOut { .. }
            | Self::VerifierOutputTooLarge { .. }
            | Self::VerifierIo { .. } => "remote.persistent.verifier_unavailable",
        }
    }

    #[cfg(target_os = "macos")]
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::VerifierIo {
            operation,
            kind: source.kind(),
            raw_os_error: source.raw_os_error(),
        }
    }
}

fn valid_team_identifier(team: &str) -> bool {
    !team.is_empty()
        && team.len() <= 64
        && team != "TEAMID"
        && team.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

#[cfg(target_os = "macos")]
fn verify_current_macos_cli(
    expected: &RemoteCliSignatureExpectation,
) -> Result<RemoteCliSignatureAttestation, RemoteCliSignatureError> {
    use std::process::Command;

    let executable = std::env::current_exe()
        .map_err(|source| RemoteCliSignatureError::io("resolve current executable", source))?;

    let display = run_bounded_command(
        Command::new("/usr/bin/codesign")
            .args(["--display", "--verbose=4"])
            .arg(&executable),
        "read current CLI code identity",
        None,
    )?;
    if !display.status.success() {
        return Err(RemoteCliSignatureError::UnsignedSignature);
    }
    let display = std::str::from_utf8(&display.stderr).map_err(|_| {
        RemoteCliSignatureError::InvalidVerifierOutput {
            field: "codesign identity UTF-8",
        }
    })?;
    if display.lines().any(|line| line == "Signature=adhoc") {
        return Err(RemoteCliSignatureError::AdHocSignature);
    }
    let code_identifier = parse_unique_codesign_value(display, "Identifier=")?;
    let team_identifier = parse_unique_codesign_value(display, "TeamIdentifier=")?;

    let requirement = format!("-R={}", expected.designated_requirement());
    let validity = run_bounded_command(
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict=all"])
            .arg(requirement)
            .arg(&executable),
        "verify current CLI designated requirement",
        None,
    )?;
    if !validity.status.success() {
        return Err(RemoteCliSignatureError::SignatureRejected);
    }

    let entitlements = run_bounded_command(
        Command::new("/usr/bin/codesign")
            .args(["--display", "--entitlements", "-", "--xml"])
            .arg(&executable),
        "read current CLI entitlements",
        None,
    )?;
    if !entitlements.status.success() {
        return Err(RemoteCliSignatureError::InvalidVerifierOutput {
            field: "codesign entitlements",
        });
    }
    let entitlement_json = parse_entitlement_plist(&entitlements.stdout)?;
    let keychain_access_groups = entitlement_json
        .get("keychain-access-groups")
        .and_then(serde_json::Value::as_array)
        .ok_or(RemoteCliSignatureError::InvalidVerifierOutput {
            field: "keychain-access-groups",
        })?
        .iter()
        .map(|value| {
            value.as_str().map(ToOwned::to_owned).ok_or(
                RemoteCliSignatureError::InvalidVerifierOutput {
                    field: "keychain-access-groups item",
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RemoteCliSignatureAttestation::new(
        RemoteCliSignatureKind::Production,
        code_identifier,
        team_identifier,
        keychain_access_groups,
    ))
}

#[cfg(target_os = "macos")]
fn parse_unique_codesign_value(
    text: &str,
    prefix: &'static str,
) -> Result<String, RemoteCliSignatureError> {
    let mut values = text.lines().filter_map(|line| line.strip_prefix(prefix));
    let value = values
        .next()
        .ok_or(RemoteCliSignatureError::InvalidVerifierOutput { field: prefix })?;
    if value.is_empty() || values.next().is_some() {
        return Err(RemoteCliSignatureError::InvalidVerifierOutput { field: prefix });
    }
    Ok(value.to_owned())
}

#[cfg(target_os = "macos")]
fn parse_entitlement_plist(xml: &[u8]) -> Result<serde_json::Value, RemoteCliSignatureError> {
    use std::process::Command;

    if xml.len() > MAX_VERIFIER_OUTPUT_BYTES {
        return Err(RemoteCliSignatureError::VerifierOutputTooLarge {
            operation: "read current CLI entitlements",
        });
    }
    let output = run_bounded_command(
        Command::new("/usr/bin/plutil").args(["-convert", "json", "-o", "-", "-"]),
        "parse current CLI entitlements",
        Some(xml),
    )?;
    if !output.status.success() {
        return Err(RemoteCliSignatureError::InvalidVerifierOutput {
            field: "entitlement plist",
        });
    }
    serde_json::from_slice(&output.stdout).map_err(|_| {
        RemoteCliSignatureError::InvalidVerifierOutput {
            field: "entitlement JSON",
        }
    })
}

#[cfg(target_os = "macos")]
struct BoundedCommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(target_os = "macos")]
struct PipeCapture {
    bytes: Vec<u8>,
    total: usize,
}

#[cfg(target_os = "macos")]
fn run_bounded_command(
    command: &mut std::process::Command,
    operation: &'static str,
    input: Option<&[u8]>,
) -> Result<BoundedCommandOutput, RemoteCliSignatureError> {
    use std::io::Write as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::Stdio;
    use std::thread;
    use std::time::Instant;

    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|source| RemoteCliSignatureError::io(operation, source))?;
    let stdout = child
        .stdout
        .take()
        .ok_or(RemoteCliSignatureError::InvalidVerifierOutput {
            field: "verifier stdout pipe",
        })?;
    let stderr = child
        .stderr
        .take()
        .ok_or(RemoteCliSignatureError::InvalidVerifierOutput {
            field: "verifier stderr pipe",
        })?;
    let stdout_reader = thread::spawn(move || read_bounded_pipe(stdout, operation));
    let stderr_reader = thread::spawn(move || read_bounded_pipe(stderr, operation));
    let input_writer = if let Some(bytes) = input {
        let bytes = bytes.to_vec();
        let mut stdin =
            child
                .stdin
                .take()
                .ok_or(RemoteCliSignatureError::InvalidVerifierOutput {
                    field: "verifier stdin pipe",
                })?;
        Some(thread::spawn(move || stdin.write_all(&bytes)))
    } else {
        None
    };

    let deadline = Instant::now() + VERIFIER_DEADLINE;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status))
                if stdout_reader.is_finished()
                    && stderr_reader.is_finished()
                    && input_writer
                        .as_ref()
                        .is_none_or(thread::JoinHandle::is_finished) =>
            {
                break status;
            }
            Ok(_) => {}
            Err(source) => {
                terminate_process_group(child);
                return Err(RemoteCliSignatureError::io(operation, source));
            }
        }
        if Instant::now() >= deadline {
            terminate_process_group(child);
            return Err(RemoteCliSignatureError::VerifierTimedOut { operation });
        }
        thread::sleep(VERIFIER_POLL_INTERVAL);
    };

    let stdout = join_pipe(stdout_reader, operation)?;
    let stderr = join_pipe(stderr_reader, operation)?;
    if let Some(writer) = input_writer {
        match writer.join() {
            Ok(Ok(())) => {}
            Ok(Err(source)) => return Err(RemoteCliSignatureError::io(operation, source)),
            Err(_) => {
                return Err(RemoteCliSignatureError::VerifierIo {
                    operation,
                    kind: io::ErrorKind::Other,
                    raw_os_error: None,
                });
            }
        }
    }
    if stdout.total.saturating_add(stderr.total) > MAX_VERIFIER_OUTPUT_BYTES {
        return Err(RemoteCliSignatureError::VerifierOutputTooLarge { operation });
    }
    Ok(BoundedCommandOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

#[cfg(target_os = "macos")]
fn read_bounded_pipe(
    mut pipe: impl io::Read,
    operation: &'static str,
) -> Result<PipeCapture, RemoteCliSignatureError> {
    let mut bytes = Vec::new();
    let mut total = 0_usize;
    let mut chunk = [0_u8; VERIFIER_PIPE_CHUNK_BYTES];
    loop {
        let read = pipe
            .read(&mut chunk)
            .map_err(|source| RemoteCliSignatureError::io(operation, source))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        if bytes.len() < MAX_VERIFIER_OUTPUT_BYTES {
            let remaining = MAX_VERIFIER_OUTPUT_BYTES - bytes.len();
            bytes.extend_from_slice(&chunk[..read.min(remaining)]);
        }
    }
    Ok(PipeCapture { bytes, total })
}

#[cfg(target_os = "macos")]
fn join_pipe(
    reader: std::thread::JoinHandle<Result<PipeCapture, RemoteCliSignatureError>>,
    operation: &'static str,
) -> Result<PipeCapture, RemoteCliSignatureError> {
    reader
        .join()
        .map_err(|_| RemoteCliSignatureError::VerifierIo {
            operation,
            kind: io::ErrorKind::Other,
            raw_os_error: None,
        })?
}

#[cfg(target_os = "macos")]
fn terminate_process_group(mut child: std::process::Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: the child was spawned into a fresh process group whose id equals its pid.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    if !matches!(child.try_wait(), Ok(Some(_))) {
        // Cleanup must not extend the verifier's absolute deadline. A detached reaper owns the
        // Child handle if SIGKILL is not yet observable; the caller returns immediately.
        let _ = std::thread::Builder::new()
            .name("agentdeck-cli-verifier-reaper".to_owned())
            .spawn(move || {
                let _ = child.wait();
            });
    }
}
