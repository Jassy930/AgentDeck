//! Persistent `remote conversations` 的完整 Catalog 分页服务。
//!
//! 本层只编排 startup recovery、exact machine open、Relay connect 与 authenticated
//! Catalog page；opaque cursor 只能逐字回传，不能由 CLI 解释、重写或持久缓存。

#![cfg(unix)]

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;

use agentdeck_crypto::rand_core::CryptoRng;
use agentdeck_protocol::runtime::identity::CatalogPageCursor;
use agentdeck_protocol::runtime::{CatalogSnapshot, ConversationEntry, StreamCursor};
use async_trait::async_trait;
use thiserror::Error;

use super::paired_machine::{PairedMachineIdentity, PairedPromotionError};
use super::production::PersistentRemoteComposition;
use super::relay_transport::{
    PairedRuntimeConnectError, PairedRuntimeConnectOutcome, RelayRuntimeTransport,
    connect_paired_runtime,
};
use super::runtime::{RemoteCatalogPageOutcome, RemoteRuntime, RemoteRuntimeError};
use super::selector::PersistentMachineSelector;

const MAX_PERSISTENT_CATALOG_PAGES: usize = 128;
const MAX_PERSISTENT_CATALOG_ENTRIES: usize = 1_024;
const MAX_PERSISTENT_CATALOG_BYTES: usize = 128 * 1024 * 1024;

/// 完整 Catalog readback；transport acceptance 只保留为独立观测，不能替代本结果。
pub struct PersistentRemoteConversationsOutcome {
    base_catalog_cursor: StreamCursor,
    conversations: Vec<ConversationEntry>,
    page_count: usize,
    route_accepted_observed: bool,
}

impl PersistentRemoteConversationsOutcome {
    #[must_use]
    pub const fn base_catalog_cursor(&self) -> StreamCursor {
        self.base_catalog_cursor
    }

    #[must_use]
    pub fn conversations(&self) -> &[ConversationEntry] {
        &self.conversations
    }

    #[must_use]
    pub const fn page_count(&self) -> usize {
        self.page_count
    }

    #[must_use]
    pub const fn route_accepted_observed(&self) -> bool {
        self.route_accepted_observed
    }
}

impl fmt::Debug for PersistentRemoteConversationsOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentRemoteConversationsOutcome")
            .field("conversation_count", &self.conversations.len())
            .field("page_count", &self.page_count)
            .field("route_accepted_observed", &self.route_accepted_observed)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum PersistentRemotePaginationError {
    #[error("Catalog base cursor changed across opaque pages")]
    BaseCursorChanged,
    #[error("Catalog opaque cursor repeated before pagination completed")]
    CursorCycle,
    #[error("Catalog pagination exceeded the 128-page client bound")]
    PageLimitExceeded,
    #[error("Catalog pagination exceeded the 1,024-entry client bound")]
    EntryLimitExceeded,
    #[error("Catalog pagination exceeded the 128 MiB client bound")]
    ByteLimitExceeded,
    #[error("Catalog pagination repeated a conversation identity")]
    DuplicateConversation,
    #[error("Catalog pagination completed without an authenticated page")]
    MissingInitialPage,
}

#[derive(Debug, Error)]
pub enum PersistentRemoteConversationsError {
    #[error("persistent paired-machine recovery or open failed")]
    Paired(#[from] PairedPromotionError),
    #[error("persistent paired-machine Relay connection failed")]
    Connect(#[from] PairedRuntimeConnectError),
    #[error("paired machine was revoked during the Relay handshake")]
    HandshakeRevoked,
    #[error("persistent remote Catalog read failed")]
    Runtime(#[from] RemoteRuntimeError),
    #[error(transparent)]
    Pagination(#[from] PersistentRemotePaginationError),
}

impl PersistentRemoteConversationsError {
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Paired(error) => error.code(),
            Self::Connect(error) => error.code(),
            Self::HandshakeRevoked => "remote.runtime.handshake_revoked",
            Self::Runtime(error) => error.code(),
            Self::Pagination(_) => "remote.runtime.catalog_pagination_invalid",
        }
    }
}

pub(super) struct CatalogPage {
    route_accepted: bool,
    snapshot: CatalogSnapshot,
}

impl CatalogPage {
    #[must_use]
    pub(super) const fn new(route_accepted: bool, snapshot: CatalogSnapshot) -> Self {
        Self {
            route_accepted,
            snapshot,
        }
    }

    fn from_runtime(outcome: &RemoteCatalogPageOutcome) -> Self {
        Self::new(outcome.route_accepted(), outcome.snapshot().clone())
    }
}

#[async_trait(?Send)]
pub(super) trait ConnectedCatalogRuntime<R>: Sized
where
    R: CryptoRng,
{
    async fn resume_pending_catalog_page(
        &mut self,
        rng: &mut R,
    ) -> Result<Option<CatalogPage>, RemoteRuntimeError>;

    async fn catalog_page(
        &mut self,
        cursor: Option<CatalogPageCursor>,
        rng: &mut R,
    ) -> Result<CatalogPage, RemoteRuntimeError>;

    async fn shutdown(self);
}

#[async_trait(?Send)]
impl<'a, R> ConnectedCatalogRuntime<R> for Box<RemoteRuntime<'a, RelayRuntimeTransport>>
where
    R: CryptoRng,
{
    async fn resume_pending_catalog_page(
        &mut self,
        rng: &mut R,
    ) -> Result<Option<CatalogPage>, RemoteRuntimeError> {
        Ok(
            RemoteRuntime::resume_pending_catalog_page(self.as_mut(), rng)
                .await?
                .as_ref()
                .map(CatalogPage::from_runtime),
        )
    }

    async fn catalog_page(
        &mut self,
        cursor: Option<CatalogPageCursor>,
        rng: &mut R,
    ) -> Result<CatalogPage, RemoteRuntimeError> {
        let outcome = RemoteRuntime::catalog_page(self.as_mut(), cursor, rng).await?;
        Ok(CatalogPage::from_runtime(&outcome))
    }

    async fn shutdown(self) {
        RemoteRuntime::shutdown(*self).await;
    }
}

pub(super) enum CatalogRuntimeConnectOutcome<T> {
    Connected(T),
    Revoked,
}

pub(super) fn checked_catalog_totals(
    current_entries: usize,
    current_bytes: usize,
    page_entries: usize,
    page_bytes: usize,
) -> Result<(usize, usize), PersistentRemotePaginationError> {
    let entries = current_entries
        .checked_add(page_entries)
        .filter(|entries| *entries <= MAX_PERSISTENT_CATALOG_ENTRIES)
        .ok_or(PersistentRemotePaginationError::EntryLimitExceeded)?;
    let bytes = current_bytes
        .checked_add(page_bytes)
        .filter(|bytes| *bytes <= MAX_PERSISTENT_CATALOG_BYTES)
        .ok_or(PersistentRemotePaginationError::ByteLimitExceeded)?;
    Ok((entries, bytes))
}

async fn collect_catalog<R, Runtime>(
    runtime: &mut Runtime,
    rng: &mut R,
) -> Result<PersistentRemoteConversationsOutcome, PersistentRemoteConversationsError>
where
    R: CryptoRng,
    Runtime: ConnectedCatalogRuntime<R>,
{
    let mut next_page_cursor = None;
    let mut issued_cursors = BTreeSet::<String>::new();
    let mut conversation_ids = BTreeSet::<String>::new();
    let mut base_catalog_cursor = None;
    let mut conversations = Vec::new();
    let mut page_count = 0_usize;
    let mut catalog_bytes = 0_usize;
    let mut route_accepted_observed = false;
    let mut recovered_first_page = runtime.resume_pending_catalog_page(rng).await?;

    loop {
        if page_count >= MAX_PERSISTENT_CATALOG_PAGES {
            return Err(PersistentRemotePaginationError::PageLimitExceeded.into());
        }
        let page = match recovered_first_page.take() {
            Some(page) => page,
            None => runtime.catalog_page(next_page_cursor.take(), rng).await?,
        };
        let page_bytes = serde_json::to_vec(&page.snapshot)
            .map_err(RemoteRuntimeError::Json)?
            .len();
        let (_, next_catalog_bytes) = checked_catalog_totals(
            conversations.len(),
            catalog_bytes,
            page.snapshot.entries().len(),
            page_bytes,
        )?;
        page_count += 1;
        catalog_bytes = next_catalog_bytes;
        route_accepted_observed |= page.route_accepted;
        match base_catalog_cursor {
            Some(expected) if page.snapshot.base_catalog_cursor != expected => {
                return Err(PersistentRemotePaginationError::BaseCursorChanged.into());
            }
            None => base_catalog_cursor = Some(page.snapshot.base_catalog_cursor),
            Some(_) => {}
        }

        for entry in page.snapshot.entries() {
            if !conversation_ids.insert(entry.conversation_id.as_str().to_owned()) {
                return Err(PersistentRemotePaginationError::DuplicateConversation.into());
            }
            conversations.push(entry.clone());
        }
        let Some(next) = page.snapshot.next_page_cursor().cloned() else {
            break;
        };
        if !issued_cursors.insert(next.as_str().to_owned()) {
            return Err(PersistentRemotePaginationError::CursorCycle.into());
        }
        next_page_cursor = Some(next);
    }

    Ok(PersistentRemoteConversationsOutcome {
        base_catalog_cursor: base_catalog_cursor
            .ok_or(PersistentRemotePaginationError::MissingInitialPage)?,
        conversations,
        page_count,
        route_accepted_observed,
    })
}

/// 测试 seam 也复用的严格 recover → open → connect → paginate → shutdown 编排。
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
    rng: &mut R,
    recover: Recover,
    open: Open,
    connect: Connect,
) -> Result<PersistentRemoteConversationsOutcome, PersistentRemoteConversationsError>
where
    R: CryptoRng,
    Runtime: ConnectedCatalogRuntime<R>,
    Recover: FnOnce() -> Result<Store, PersistentRemoteConversationsError>,
    Open:
        FnOnce(Store, PairedMachineIdentity) -> Result<Machine, PersistentRemoteConversationsError>,
    Connect: FnOnce(Machine) -> ConnectFuture,
    ConnectFuture: Future<
        Output = Result<CatalogRuntimeConnectOutcome<Runtime>, PersistentRemoteConversationsError>,
    >,
{
    let recovered = recover()?;
    let machine = open(recovered, selector.identity())?;
    let mut runtime = match connect(machine).await? {
        CatalogRuntimeConnectOutcome::Connected(runtime) => runtime,
        CatalogRuntimeConnectOutcome::Revoked => {
            return Err(PersistentRemoteConversationsError::HandshakeRevoked);
        }
    };

    let result = collect_catalog(&mut runtime, rng).await;
    runtime.shutdown().await;
    result
}

/// Production CLI 的唯一 persistent remote Catalog 入口。
pub async fn list_persistent_remote_conversations<R>(
    composition: &PersistentRemoteComposition,
    selector: PersistentMachineSelector,
    rng: &mut R,
) -> Result<PersistentRemoteConversationsOutcome, PersistentRemoteConversationsError>
where
    R: CryptoRng,
{
    execute_with(
        selector,
        rng,
        || {
            composition
                .recovered_paired_machine_store()
                .map_err(PersistentRemoteConversationsError::Paired)
        },
        |recovered, identity| {
            recovered
                .open_exact(identity)
                .map_err(PersistentRemoteConversationsError::Paired)
        },
        |machine| async move {
            match connect_paired_runtime(machine)
                .await
                .map_err(PersistentRemoteConversationsError::Connect)?
            {
                PairedRuntimeConnectOutcome::Connected(runtime) => {
                    Ok(CatalogRuntimeConnectOutcome::Connected(runtime))
                }
                PairedRuntimeConnectOutcome::Revoked => Ok(CatalogRuntimeConnectOutcome::Revoked),
            }
        },
    )
    .await
}
