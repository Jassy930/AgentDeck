//! Admin 请求到 Store/Core actor 的唯一翻译层。

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_crypto::sha256;
use agentdeck_protocol::relay_v2::{EnrollmentCode, MachineRouteId};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use rand::RngCore;

use crate::v2::auth::AuthorizationCoordinator;
use crate::v2::core::RelayCore;
use crate::v2::store::{
    EnrollmentCodeSeed, MAX_MACHINE_INVENTORY_PAGE, MachineInventoryQuery, MachineReadbackQuery,
    PurgeMachine, RelayStoreHandle, StoreError,
};

use super::protocol::{
    ADMIN_PROTOCOL_VERSION, AdminFailure, AdminRequest, AdminResponse, AdminResult, Digest32,
    EnrollmentBundleV1,
};
use super::{AdminClient, AdminClientError};

pub const ENROLLMENT_CODE_TTL_MS: u64 = 5 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRuntimeConfig {
    pub public_wss_url: String,
    pub spki_pins: Vec<[u8; 32]>,
}

#[derive(Clone)]
pub struct AdminCommandExecutor {
    store: RelayStoreHandle,
    authorization: AuthorizationCoordinator,
    core: RelayCore,
    runtime: AdminRuntimeConfig,
}

impl std::fmt::Debug for AdminCommandExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminCommandExecutor")
            .finish_non_exhaustive()
    }
}

impl AdminCommandExecutor {
    pub fn new(
        store: RelayStoreHandle,
        authorization: AuthorizationCoordinator,
        core: RelayCore,
        runtime: AdminRuntimeConfig,
    ) -> Self {
        Self {
            store,
            authorization,
            core,
            runtime,
        }
    }

    pub async fn execute(&self, request: AdminRequest) -> AdminResponse {
        match self.try_execute(request).await {
            Ok(result) => AdminResponse::Ok { result },
            Err(code) => AdminResponse::Error {
                error: AdminFailure {
                    code: code.to_owned(),
                },
            },
        }
    }

    async fn try_execute(&self, request: AdminRequest) -> Result<AdminResult, &'static str> {
        match request {
            AdminRequest::MachineEnrollCreate {} => self.create_enrollment_bundle().await,
            AdminRequest::MachineInventory { after } => {
                let page = self
                    .store
                    .machine_inventory(MachineInventoryQuery {
                        after,
                        limit: MAX_MACHINE_INVENTORY_PAGE,
                    })
                    .await
                    .map_err(store_code)?;
                Ok(AdminResult::MachineInventory { page: page.into() })
            }
            AdminRequest::MachineReadback {
                machine_route,
                confirm_root_fingerprint,
            } => {
                let readback = self
                    .store
                    .machine_readback(MachineReadbackQuery {
                        machine_route,
                        expected_root_fingerprint: confirm_root_fingerprint.0,
                    })
                    .await
                    .map_err(store_code)?;
                Ok(AdminResult::MachineReadback {
                    readback: readback.into(),
                })
            }
            AdminRequest::MachinePurge {
                machine_route,
                confirm_root_fingerprint,
            } => {
                let readback = self
                    .core
                    .purge_machine_admin(PurgeMachine {
                        machine_route,
                        expected_root_fingerprint: confirm_root_fingerprint.0,
                    })
                    .await
                    .map_err(store_code)?;
                Ok(AdminResult::MachinePurged {
                    readback: readback.into(),
                })
            }
        }
    }

    async fn create_enrollment_bundle(&self) -> Result<AdminResult, &'static str> {
        let mut code = EnrollmentCode([0_u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut code.0)
            .map_err(|_| "relay.admin.random_unavailable")?;
        let expires_at_ms = unix_now_ms().saturating_add(ENROLLMENT_CODE_TTL_MS);
        self.authorization
            .seed_enrollment_code(EnrollmentCodeSeed {
                code_hash: sha256(&code.0),
                expires_at_ms,
            })
            .await
            .map_err(store_code)?;
        Ok(AdminResult::EnrollmentBundle {
            bundle: EnrollmentBundleV1 {
                version: ADMIN_PROTOCOL_VERSION,
                public_wss_url: self.runtime.public_wss_url.clone(),
                relay_server_id: self.store.relay_server_id(),
                code,
                spki_pins: self
                    .runtime
                    .spki_pins
                    .iter()
                    .copied()
                    .map(Digest32)
                    .collect(),
                expires_at_ms,
            },
        })
    }
}

fn store_code(error: StoreError) -> &'static str {
    error.diagnostic_code()
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

#[derive(Debug, thiserror::Error)]
pub enum AdminCliError {
    #[error("admin command-line parse failed")]
    Parse(#[source] clap::Error),
    #[error("admin socket is required")]
    MissingSocket,
    #[error("admin command value is invalid: {field}")]
    InvalidValue { field: &'static str },
    #[error("admin client failed")]
    Client(#[source] AdminClientError),
    #[error("admin response serialization failed")]
    Serialization,
}

impl AdminCliError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Parse(_) => "relay.admin.cli_parse",
            Self::MissingSocket => "relay.admin.socket_required",
            Self::InvalidValue { .. } => "relay.admin.cli_value_invalid",
            Self::Client(error) => error.code(),
            Self::Serialization => "relay.admin.response_invalid",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AdminCliOutput {
    pub json: String,
    pub success: bool,
}

impl std::fmt::Debug for AdminCliOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminCliOutput")
            .field("success", &self.success)
            .field("json", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Parser)]
#[command(name = "agentdeck-relay", disable_help_subcommand = true)]
struct AdminCliArgs {
    #[arg(long, global = true)]
    admin_socket: Option<PathBuf>,
    #[command(subcommand)]
    command: AdminTopLevel,
}

#[derive(Debug, Subcommand)]
enum AdminTopLevel {
    MachineEnroll {
        #[command(subcommand)]
        command: MachineEnrollCommand,
    },
    Machine {
        #[command(subcommand)]
        command: MachineCommand,
    },
}

#[derive(Debug, Subcommand)]
enum MachineEnrollCommand {
    Create,
}

#[derive(Debug, Subcommand)]
enum MachineCommand {
    Inventory {
        #[arg(long)]
        after: Option<String>,
    },
    Readback {
        machine_route: String,
        #[arg(long)]
        confirm: String,
    },
    Purge {
        machine_route: String,
        #[arg(long)]
        confirm: String,
    },
}

/// 非 admin argv 返回 `Ok(None)`，让 production binary 继续进入 server 配置路径。
/// admin argv 只连接本机 UDS，并把完整响应编码为单行 JSON 交给 main 输出。
pub async fn execute_admin_cli<I, T>(
    args: I,
    environment_socket: Option<PathBuf>,
) -> Result<Option<AdminCliOutput>, AdminCliError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let first = args.get(1).and_then(|value| value.to_str());
    let command_index = match first {
        Some("--admin-socket") => 3,
        Some(value) if value.starts_with("--admin-socket=") => 2,
        _ => 1,
    };
    let is_admin = args
        .get(command_index)
        .and_then(|value| value.to_str())
        .is_some_and(|value| matches!(value, "machine-enroll" | "machine"));
    if !is_admin {
        return Ok(None);
    }
    let parsed = AdminCliArgs::try_parse_from(args).map_err(AdminCliError::Parse)?;
    let socket = parsed
        .admin_socket
        .or(environment_socket)
        .ok_or(AdminCliError::MissingSocket)?;
    let request = match parsed.command {
        AdminTopLevel::MachineEnroll {
            command: MachineEnrollCommand::Create,
        } => AdminRequest::MachineEnrollCreate {},
        AdminTopLevel::Machine {
            command: MachineCommand::Inventory { after },
        } => AdminRequest::MachineInventory {
            after: after.map(|value| parse_route(&value)).transpose()?,
        },
        AdminTopLevel::Machine {
            command:
                MachineCommand::Readback {
                    machine_route,
                    confirm,
                },
        } => AdminRequest::MachineReadback {
            machine_route: parse_route(&machine_route)?,
            confirm_root_fingerprint: Digest32(parse_digest(&confirm, "confirm")?),
        },
        AdminTopLevel::Machine {
            command:
                MachineCommand::Purge {
                    machine_route,
                    confirm,
                },
        } => AdminRequest::MachinePurge {
            machine_route: parse_route(&machine_route)?,
            confirm_root_fingerprint: Digest32(parse_digest(&confirm, "confirm")?),
        },
    };
    let response = AdminClient::new(socket)
        .request(&request)
        .await
        .map_err(AdminCliError::Client)?;
    let success = matches!(response, AdminResponse::Ok { .. });
    let json = serde_json::to_string(&response).map_err(|_| AdminCliError::Serialization)?;
    Ok(Some(AdminCliOutput { json, success }))
}

fn parse_route(value: &str) -> Result<MachineRouteId, AdminCliError> {
    let bytes = STANDARD
        .decode(value.as_bytes())
        .map_err(|_| AdminCliError::InvalidValue {
            field: "machine_route",
        })?;
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| AdminCliError::InvalidValue {
        field: "machine_route",
    })?;
    if STANDARD.encode(bytes) != value {
        return Err(AdminCliError::InvalidValue {
            field: "machine_route",
        });
    }
    Ok(MachineRouteId::from_bytes(bytes))
}

fn parse_digest(value: &str, field: &'static str) -> Result<[u8; 32], AdminCliError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| AdminCliError::InvalidValue { field })?;
    bytes
        .try_into()
        .map_err(|_| AdminCliError::InvalidValue { field })
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[tokio::test]
    async fn unrelated_argv_is_not_consumed_and_admin_values_fail_before_socket_io() {
        assert!(
            execute_admin_cli(["agentdeck-relay", "--selfcheck"], None)
                .await
                .expect("non-admin argv")
                .is_none()
        );
        assert!(
            execute_admin_cli(
                [
                    "agentdeck-relay",
                    "--selfcheck",
                    "--bootstrap-secret",
                    "s",
                    "--storage",
                    "machine",
                ],
                None,
            )
            .await
            .expect("legacy server argument values are not subcommands")
            .is_none()
        );
        let error = execute_admin_cli(
            [
                "agentdeck-relay",
                "machine",
                "purge",
                "not-a-route",
                "--confirm",
                "not-a-fingerprint",
                "--admin-socket",
                "/tmp/does-not-matter.sock",
            ],
            None,
        )
        .await
        .expect_err("invalid route is rejected before connect");
        assert!(matches!(
            error,
            AdminCliError::InvalidValue {
                field: "machine_route"
            }
        ));
        let route = MachineRouteId::from_bytes([0x5a; 16]);
        let wire = serde_json::to_string(&route).expect("route wire");
        assert_eq!(
            parse_route(wire.trim_matches('"')).expect("inventory route must feed CLI"),
            route
        );
        let output = AdminCliOutput {
            json: "{\"code\":\"ONE_TIME_SECRET\"}".to_owned(),
            success: true,
        };
        assert!(!format!("{output:?}").contains("ONE_TIME_SECRET"));
    }
}
