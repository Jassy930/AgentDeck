//! Persistent remote CLI mutation 的唯一 composition 与 lifecycle 边界。
//!
//! recovery、exact open 与 Relay connect 严格串行；只有 `Connected` 才能进入 Runtime。
//! 非 consuming 命令在成功和错误路径都显式等待 shutdown，self-revoke 则完全委托给
//! `RemoteRuntime::revoke_self` 的 shutdown → transport drop → cleanup 顺序。

#![cfg(unix)]

use std::fmt;
use std::future::Future;

use agentdeck_crypto::rand_core::CryptoRng;
use agentdeck_protocol::ActionDecision;
use agentdeck_protocol::runtime::identity::{ApprovalId, TurnId};
use agentdeck_protocol::runtime::{
    ApprovalReceipt, CommandReceipt, ConversationId, RevocationReceipt, SendPromptRequest,
};
use async_trait::async_trait;
use thiserror::Error;

use super::paired_machine::{PairedMachineIdentity, PairedPromotionError};
use super::production::PersistentRemoteComposition;
use super::relay_transport::{
    PairedRuntimeConnectError, PairedRuntimeConnectOutcome, RelayRuntimeTransport,
    connect_paired_runtime,
};
use super::runtime::{RemoteRuntime, RemoteRuntimeError, RemoteRuntimeTransportError};
use super::selector::PersistentMachineSelector;

/// 已完成 CLI 参数校验的 persistent remote mutation。
pub enum PersistentRemoteMutation {
    Prompt(SendPromptRequest),
    ResolveApproval {
        conversation_id: ConversationId,
        turn_id: TurnId,
        approval_id: ApprovalId,
        decision: ActionDecision,
    },
    RetryApproval {
        conversation_id: ConversationId,
        approval_id: ApprovalId,
    },
    RevokeSelf,
}

impl fmt::Debug for PersistentRemoteMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Prompt(_) => "PersistentRemoteMutation::Prompt([REDACTED])",
            Self::ResolveApproval { .. } => "PersistentRemoteMutation::ResolveApproval([REDACTED])",
            Self::RetryApproval { .. } => "PersistentRemoteMutation::RetryApproval([REDACTED])",
            Self::RevokeSelf => "PersistentRemoteMutation::RevokeSelf",
        })
    }
}

/// authenticated daemon/root terminal 与独立 RouteAccepted 观测。
#[derive(Debug)]
pub enum PersistentRemoteMutationOutcome {
    Prompt {
        route_accepted: bool,
        receipt: CommandReceipt,
    },
    Approval {
        route_accepted: bool,
        receipt: ApprovalReceipt,
    },
    Revocation {
        route_accepted: bool,
        receipt: RevocationReceipt,
    },
}

impl PersistentRemoteMutationOutcome {
    #[must_use]
    pub const fn route_accepted(&self) -> bool {
        match self {
            Self::Prompt { route_accepted, .. }
            | Self::Approval { route_accepted, .. }
            | Self::Revocation { route_accepted, .. } => *route_accepted,
        }
    }
}

/// Persistent mutation 组合层失败；任一 variant 都不是业务成功。
#[derive(Debug, Error)]
pub enum PersistentRemoteMutationError {
    #[error("persistent paired-machine recovery or open failed")]
    Paired(#[from] PairedPromotionError),
    #[error("persistent paired-machine Relay connection failed")]
    Connect(#[from] PairedRuntimeConnectError),
    #[error("paired machine was revoked during the Relay handshake")]
    HandshakeRevoked,
    #[error("persistent remote Runtime mutation failed")]
    Runtime(#[from] RemoteRuntimeError),
}

impl PersistentRemoteMutationError {
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Paired(error) => error.code(),
            Self::Connect(error) => error.code(),
            Self::HandshakeRevoked => "remote.runtime.handshake_revoked",
            Self::Runtime(error) => remote_runtime_error_code(error),
        }
    }
}

fn remote_runtime_error_code(error: &RemoteRuntimeError) -> &str {
    match error {
        RemoteRuntimeError::Paired(error) => error.code(),
        RemoteRuntimeError::Transport(RemoteRuntimeTransportError::Relay(error)) => error.code(),
        RemoteRuntimeError::Transport(RemoteRuntimeTransportError::Failed(_)) => {
            "remote.runtime.transport_failed"
        }
        RemoteRuntimeError::RelayCodec(_) => "remote.runtime.relay_frame_invalid",
        RemoteRuntimeError::Json(_) | RemoteRuntimeError::InvalidReply(_) => {
            "remote.runtime.reply_invalid"
        }
        RemoteRuntimeError::EntropyUnavailable => "remote.runtime.entropy_unavailable",
        RemoteRuntimeError::PendingIntentConflict => "remote.runtime.pending_intent_conflict",
        RemoteRuntimeError::DaemonFailure(failure) => failure.code.as_str(),
        RemoteRuntimeError::OutcomeUnknown => "remote.runtime.outcome_unknown",
        RemoteRuntimeError::TransferUnsupported => "remote.runtime.transfer_unsupported",
        RemoteRuntimeError::ReplayRejected => "remote.runtime.replay_rejected",
        RemoteRuntimeError::InvalidDurableState => "remote.runtime.state_invalid",
    }
}

pub(super) enum RuntimeConnectOutcome<T> {
    Connected(T),
    Revoked,
}

/// Automatic harness 可替换的最小 connected Runtime seam。
#[async_trait(?Send)]
pub(super) trait ConnectedMutationRuntime<R>: Sized
where
    R: CryptoRng,
{
    async fn execute_non_revoking(
        &mut self,
        mutation: PersistentRemoteMutation,
        rng: &mut R,
    ) -> Result<PersistentRemoteMutationOutcome, RemoteRuntimeError>;

    async fn shutdown(self);

    async fn revoke_self(
        self,
        rng: &mut R,
    ) -> Result<PersistentRemoteMutationOutcome, RemoteRuntimeError>;
}

#[async_trait(?Send)]
impl<'a, R> ConnectedMutationRuntime<R> for Box<RemoteRuntime<'a, RelayRuntimeTransport>>
where
    R: CryptoRng,
{
    async fn execute_non_revoking(
        &mut self,
        mutation: PersistentRemoteMutation,
        rng: &mut R,
    ) -> Result<PersistentRemoteMutationOutcome, RemoteRuntimeError> {
        match mutation {
            PersistentRemoteMutation::Prompt(request) => {
                let outcome = RemoteRuntime::prompt(self.as_mut(), request, rng).await?;
                Ok(PersistentRemoteMutationOutcome::Prompt {
                    route_accepted: outcome.route_accepted(),
                    receipt: outcome.receipt().clone(),
                })
            }
            PersistentRemoteMutation::ResolveApproval {
                conversation_id,
                turn_id,
                approval_id,
                decision,
            } => {
                let outcome = RemoteRuntime::resolve_approval(
                    self.as_mut(),
                    conversation_id,
                    turn_id,
                    approval_id,
                    decision,
                    rng,
                )
                .await?;
                Ok(PersistentRemoteMutationOutcome::Approval {
                    route_accepted: outcome.route_accepted(),
                    receipt: outcome.receipt().clone(),
                })
            }
            PersistentRemoteMutation::RetryApproval {
                conversation_id,
                approval_id,
            } => {
                let outcome =
                    RemoteRuntime::retry_approval(self.as_mut(), conversation_id, approval_id, rng)
                        .await?;
                Ok(PersistentRemoteMutationOutcome::Approval {
                    route_accepted: outcome.route_accepted(),
                    receipt: outcome.receipt().clone(),
                })
            }
            PersistentRemoteMutation::RevokeSelf => {
                unreachable!("self-revoke must use the consuming Runtime path")
            }
        }
    }

    async fn shutdown(self) {
        RemoteRuntime::shutdown(*self).await;
    }

    async fn revoke_self(
        self,
        rng: &mut R,
    ) -> Result<PersistentRemoteMutationOutcome, RemoteRuntimeError> {
        let outcome = RemoteRuntime::revoke_self(*self, rng).await?;
        Ok(PersistentRemoteMutationOutcome::Revocation {
            route_accepted: outcome.route_accepted(),
            receipt: outcome.receipt().clone(),
        })
    }
}

/// 测试 seam 也复用的严格 recover → open → connect → dispatch 编排。
pub(super) async fn execute_with<
    R,
    Store,
    Machine,
    Runtime,
    Recover,
    Open,
    Connect,
    ConnectFuture,
>(
    selector: PersistentMachineSelector,
    mutation: PersistentRemoteMutation,
    rng: &mut R,
    recover: Recover,
    open: Open,
    connect: Connect,
) -> Result<PersistentRemoteMutationOutcome, PersistentRemoteMutationError>
where
    R: CryptoRng,
    Runtime: ConnectedMutationRuntime<R>,
    Recover: FnOnce() -> Result<Store, PersistentRemoteMutationError>,
    Open: FnOnce(Store, PairedMachineIdentity) -> Result<Machine, PersistentRemoteMutationError>,
    Connect: FnOnce(Machine) -> ConnectFuture,
    ConnectFuture:
        Future<Output = Result<RuntimeConnectOutcome<Runtime>, PersistentRemoteMutationError>>,
{
    let recovered = recover()?;
    let machine = open(recovered, selector.identity())?;
    let runtime = match connect(machine).await? {
        RuntimeConnectOutcome::Connected(runtime) => runtime,
        RuntimeConnectOutcome::Revoked => {
            return Err(PersistentRemoteMutationError::HandshakeRevoked);
        }
    };

    if matches!(mutation, PersistentRemoteMutation::RevokeSelf) {
        return runtime
            .revoke_self(rng)
            .await
            .map_err(PersistentRemoteMutationError::Runtime);
    }

    let mut runtime = runtime;
    let result = runtime.execute_non_revoking(mutation, rng).await;
    runtime.shutdown().await;
    result.map_err(PersistentRemoteMutationError::Runtime)
}

/// Production CLI 的唯一 persistent remote mutation 入口。
pub async fn execute_persistent_remote_mutation<R>(
    composition: &PersistentRemoteComposition,
    selector: PersistentMachineSelector,
    mutation: PersistentRemoteMutation,
    rng: &mut R,
) -> Result<PersistentRemoteMutationOutcome, PersistentRemoteMutationError>
where
    R: CryptoRng,
{
    execute_with(
        selector,
        mutation,
        rng,
        || {
            composition
                .recovered_paired_machine_store()
                .map_err(PersistentRemoteMutationError::Paired)
        },
        |recovered, identity| {
            recovered
                .open_exact(identity)
                .map_err(PersistentRemoteMutationError::Paired)
        },
        |machine| async move {
            match connect_paired_runtime(machine)
                .await
                .map_err(PersistentRemoteMutationError::Connect)?
            {
                PairedRuntimeConnectOutcome::Connected(runtime) => {
                    Ok(RuntimeConnectOutcome::Connected(runtime))
                }
                PairedRuntimeConnectOutcome::Revoked => Ok(RuntimeConnectOutcome::Revoked),
            }
        },
    )
    .await
}
