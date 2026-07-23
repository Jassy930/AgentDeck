use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use agentdeck_crypto::rand_core::{Infallible, TryCryptoRng, TryRng};
use agentdeck_protocol::AgentKind;
use agentdeck_protocol::runtime::identity::CatalogPageCursor;
use agentdeck_protocol::runtime::{
    CatalogSnapshot, ConversationEntry, ConversationId, StreamCursor,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::conversations::{
    CatalogPage, CatalogRuntimeConnectOutcome, ConnectedCatalogRuntime,
    PersistentRemoteConversationsError, PersistentRemotePaginationError, checked_catalog_totals,
    execute_with,
};
use super::paired_machine::{PairedMachineIdentity, PairedPromotionError};
use super::runtime::RemoteRuntimeError;
use super::selector::PersistentMachineSelector;

#[derive(Default)]
struct DeterministicRng(u8);

impl TryRng for DeterministicRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dest {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

impl TryCryptoRng for DeterministicRng {}

struct FakeRuntime {
    recovered_first_page: Option<CatalogPage>,
    pages: VecDeque<Result<CatalogPage, RemoteRuntimeError>>,
    requested: Arc<Mutex<Vec<Option<String>>>>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait(?Send)]
impl ConnectedCatalogRuntime<DeterministicRng> for FakeRuntime {
    async fn resume_pending_catalog_page(
        &mut self,
        _rng: &mut DeterministicRng,
    ) -> Result<Option<CatalogPage>, RemoteRuntimeError> {
        self.events
            .lock()
            .expect("event recorder")
            .push("resume_catalog");
        Ok(self.recovered_first_page.take())
    }

    async fn catalog_page(
        &mut self,
        cursor: Option<CatalogPageCursor>,
        _rng: &mut DeterministicRng,
    ) -> Result<CatalogPage, RemoteRuntimeError> {
        self.events.lock().expect("event recorder").push("catalog");
        self.requested
            .lock()
            .expect("cursor recorder")
            .push(cursor.map(|value| value.as_str().to_owned()));
        self.pages
            .pop_front()
            .expect("fake runtime page script exhausted")
    }

    async fn shutdown(self) {
        self.events
            .lock()
            .expect("event recorder")
            .push("shutdown_start");
        tokio::task::yield_now().await;
        self.events
            .lock()
            .expect("event recorder")
            .push("shutdown_complete");
    }
}

impl Drop for FakeRuntime {
    fn drop(&mut self) {
        self.events
            .lock()
            .expect("event recorder")
            .push("runtime_drop");
    }
}

fn selector() -> PersistentMachineSelector {
    PersistentMachineSelector::parse(&STANDARD.encode([0x11; 32]), &STANDARD.encode([0x22; 16]))
        .expect("canonical selector")
}

fn snapshot(base: StreamCursor, conversation: &str, next: Option<&str>) -> CatalogSnapshot {
    CatalogSnapshot::new(
        base,
        vec![ConversationEntry {
            conversation_id: ConversationId::new(conversation),
            agent_kind: AgentKind::Codex,
            title: Some(format!("title-{conversation}")),
            cwd: None,
            last_active_ms: 7,
            archived: false,
            entry_revision: 1,
        }],
        next.map(CatalogPageCursor::new),
    )
    .expect("valid Catalog page")
}

fn snapshot_range(
    base: StreamCursor,
    start: usize,
    count: usize,
    next: Option<String>,
) -> CatalogSnapshot {
    CatalogSnapshot::new(
        base,
        (start..start + count)
            .map(|index| ConversationEntry {
                conversation_id: ConversationId::new(format!("conversation-{index}")),
                agent_kind: AgentKind::Codex,
                title: Some(format!("title-{index}")),
                cwd: None,
                last_active_ms: index as u64,
                archived: false,
                entry_revision: 1,
            })
            .collect(),
        next.map(CatalogPageCursor::new),
    )
    .expect("bounded Catalog page")
}

fn page(
    route_accepted: bool,
    base: StreamCursor,
    conversation: &str,
    next: Option<&str>,
) -> Result<CatalogPage, RemoteRuntimeError> {
    Ok(CatalogPage::new(
        route_accepted,
        snapshot(base, conversation, next),
    ))
}

async fn execute_fake(
    recovered_first_page: Option<CatalogPage>,
    pages: Vec<Result<CatalogPage, RemoteRuntimeError>>,
    events: Arc<Mutex<Vec<&'static str>>>,
    requested: Arc<Mutex<Vec<Option<String>>>>,
) -> Result<
    super::conversations::PersistentRemoteConversationsOutcome,
    PersistentRemoteConversationsError,
> {
    let recover_events = Arc::clone(&events);
    let open_events = Arc::clone(&events);
    let connect_events = Arc::clone(&events);
    let runtime_events = Arc::clone(&events);
    execute_with(
        selector(),
        &mut DeterministicRng::default(),
        move || {
            recover_events
                .lock()
                .expect("event recorder")
                .push("recover");
            Ok(())
        },
        move |(), identity| {
            open_events
                .lock()
                .expect("event recorder")
                .push("open_exact");
            assert_eq!(identity, selector().identity());
            Ok(identity)
        },
        move |machine: PairedMachineIdentity| async move {
            connect_events
                .lock()
                .expect("event recorder")
                .push("connect");
            assert_eq!(machine, selector().identity());
            Ok(CatalogRuntimeConnectOutcome::Connected(FakeRuntime {
                recovered_first_page,
                pages: pages.into(),
                requested,
                events: runtime_events,
            }))
        },
    )
    .await
}

#[tokio::test]
async fn opaque_cursor_pages_are_followed_exactly_and_shutdown_precedes_success() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let requested = Arc::new(Mutex::new(Vec::new()));
    let base = StreamCursor::At(17);
    let outcome = execute_fake(
        None,
        vec![
            page(false, base, "conversation-1", Some("opaque-A")),
            page(true, base, "conversation-2", Some("opaque-B")),
            page(false, base, "conversation-3", None),
        ],
        Arc::clone(&events),
        Arc::clone(&requested),
    )
    .await
    .expect("all authenticated Catalog pages");

    assert_eq!(outcome.base_catalog_cursor(), base);
    assert_eq!(outcome.page_count(), 3);
    assert!(outcome.route_accepted_observed());
    assert_eq!(
        outcome
            .conversations()
            .iter()
            .map(|entry| entry.conversation_id.as_str())
            .collect::<Vec<_>>(),
        ["conversation-1", "conversation-2", "conversation-3"]
    );
    assert_eq!(
        *requested.lock().expect("cursor recorder"),
        [
            None,
            Some("opaque-A".to_owned()),
            Some("opaque-B".to_owned()),
        ]
    );
    assert_eq!(
        *events.lock().expect("event recorder"),
        [
            "recover",
            "open_exact",
            "connect",
            "resume_catalog",
            "catalog",
            "catalog",
            "catalog",
            "shutdown_start",
            "shutdown_complete",
            "runtime_drop",
        ]
    );
}

#[tokio::test]
async fn recovered_first_page_continues_exact_cursor_and_route_acceptance_is_not_success() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let requested = Arc::new(Mutex::new(Vec::new()));
    let base = StreamCursor::At(23);
    let recovered = page(
        false,
        base,
        "conversation-recovered",
        Some("opaque-resumed"),
    )
    .expect("recovered first page");
    let outcome = execute_fake(
        Some(recovered),
        vec![page(false, base, "conversation-final", None)],
        Arc::clone(&events),
        Arc::clone(&requested),
    )
    .await
    .expect("authenticated Catalog is success without RouteAccepted observation");

    assert!(!outcome.route_accepted_observed());
    assert_eq!(outcome.page_count(), 2);
    assert_eq!(
        *requested.lock().expect("cursor recorder"),
        [Some("opaque-resumed".to_owned())]
    );
    assert!(events.lock().expect("event recorder").ends_with(&[
        "shutdown_start",
        "shutdown_complete",
        "runtime_drop"
    ]));
}

#[tokio::test]
async fn page_entry_and_duplicate_limits_fail_closed_and_shutdown() {
    let base = StreamCursor::At(31);
    let page_limit = (0..128)
        .map(|index| {
            Ok(CatalogPage::new(
                false,
                snapshot_range(base, index, 1, Some(format!("opaque-page-{index}"))),
            ))
        })
        .collect::<Vec<_>>();
    let entry_limit = vec![
        Ok(CatalogPage::new(
            false,
            snapshot_range(base, 0, 500, Some("opaque-entry-A".to_owned())),
        )),
        Ok(CatalogPage::new(
            false,
            snapshot_range(base, 500, 500, Some("opaque-entry-B".to_owned())),
        )),
        Ok(CatalogPage::new(
            false,
            snapshot_range(base, 1_000, 25, None),
        )),
    ];
    let duplicate = vec![
        page(
            false,
            base,
            "conversation-duplicate",
            Some("opaque-duplicate"),
        ),
        page(false, base, "conversation-duplicate", None),
    ];

    for (pages, expected) in [
        (
            page_limit,
            PersistentRemotePaginationError::PageLimitExceeded,
        ),
        (
            entry_limit,
            PersistentRemotePaginationError::EntryLimitExceeded,
        ),
        (
            duplicate,
            PersistentRemotePaginationError::DuplicateConversation,
        ),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let error = execute_fake(
            None,
            pages,
            Arc::clone(&events),
            Arc::new(Mutex::new(Vec::new())),
        )
        .await
        .expect_err("invalid pagination must fail closed");
        assert!(matches!(
            error,
            PersistentRemoteConversationsError::Pagination(observed) if observed == expected
        ));
        assert!(events.lock().expect("event recorder").ends_with(&[
            "shutdown_start",
            "shutdown_complete",
            "runtime_drop"
        ]));
    }
}

#[test]
fn aggregate_catalog_byte_and_entry_bounds_are_checked_without_large_allocations() {
    assert_eq!(
        checked_catalog_totals(1_023, 128 * 1024 * 1024 - 1, 1, 1),
        Ok((1_024, 128 * 1024 * 1024))
    );
    assert_eq!(
        checked_catalog_totals(1_024, 0, 1, 0),
        Err(PersistentRemotePaginationError::EntryLimitExceeded)
    );
    assert_eq!(
        checked_catalog_totals(0, 128 * 1024 * 1024, 0, 1),
        Err(PersistentRemotePaginationError::ByteLimitExceeded)
    );
}

#[tokio::test]
async fn base_drift_cursor_cycle_and_runtime_failure_all_shutdown_fail_closed() {
    let cases = [
        vec![
            page(
                false,
                StreamCursor::At(1),
                "conversation-1",
                Some("opaque-A"),
            ),
            page(false, StreamCursor::At(2), "conversation-2", None),
        ],
        vec![
            page(
                false,
                StreamCursor::At(1),
                "conversation-1",
                Some("opaque-A"),
            ),
            page(
                false,
                StreamCursor::At(1),
                "conversation-2",
                Some("opaque-A"),
            ),
        ],
        vec![Err(RemoteRuntimeError::OutcomeUnknown)],
    ];

    for pages in cases {
        let events = Arc::new(Mutex::new(Vec::new()));
        let error = execute_fake(
            None,
            pages,
            Arc::clone(&events),
            Arc::new(Mutex::new(Vec::new())),
        )
        .await
        .expect_err("invalid or incomplete pagination cannot be success");
        assert!(matches!(
            error,
            PersistentRemoteConversationsError::Pagination(_)
                | PersistentRemoteConversationsError::Runtime(RemoteRuntimeError::OutcomeUnknown)
        ));
        assert!(events.lock().expect("event recorder").ends_with(&[
            "shutdown_start",
            "shutdown_complete",
            "runtime_drop"
        ]));
    }
}

#[tokio::test]
async fn recovery_open_and_revoked_handshake_never_enter_catalog_dispatch() {
    let connector_calls = Arc::new(Mutex::new(0_usize));
    let calls = Arc::clone(&connector_calls);
    let recovery_error = execute_with(
        selector(),
        &mut DeterministicRng::default(),
        || Err::<(), _>(PairedPromotionError::InvalidState.into()),
        |(), _| Ok::<_, PersistentRemoteConversationsError>(()),
        move |()| async move {
            *calls.lock().expect("connector calls") += 1;
            Ok(CatalogRuntimeConnectOutcome::Connected(FakeRuntime {
                recovered_first_page: None,
                pages: VecDeque::new(),
                requested: Arc::new(Mutex::new(Vec::new())),
                events: Arc::new(Mutex::new(Vec::new())),
            }))
        },
    )
    .await
    .expect_err("recovery must fail closed");
    assert_eq!(recovery_error.code(), "remote.pairing.paired_invalid");
    assert_eq!(*connector_calls.lock().expect("connector calls"), 0);

    let calls = Arc::clone(&connector_calls);
    let open_error = execute_with(
        selector(),
        &mut DeterministicRng::default(),
        || Ok(()),
        |(), _| Err::<PairedMachineIdentity, _>(PairedPromotionError::InvalidState.into()),
        move |_machine| async move {
            *calls.lock().expect("connector calls") += 1;
            Ok(CatalogRuntimeConnectOutcome::Connected(FakeRuntime {
                recovered_first_page: None,
                pages: VecDeque::new(),
                requested: Arc::new(Mutex::new(Vec::new())),
                events: Arc::new(Mutex::new(Vec::new())),
            }))
        },
    )
    .await
    .expect_err("exact machine open must fail closed");
    assert_eq!(open_error.code(), "remote.pairing.paired_invalid");
    assert_eq!(*connector_calls.lock().expect("connector calls"), 0);

    let revoked = execute_with(
        selector(),
        &mut DeterministicRng::default(),
        || Ok(()),
        |(), identity| Ok(identity),
        |_machine| async { Ok(CatalogRuntimeConnectOutcome::<FakeRuntime>::Revoked) },
    )
    .await
    .expect_err("revoked handshake cannot list conversations");
    assert_eq!(revoked.code(), "remote.runtime.handshake_revoked");
}

#[test]
fn production_adapter_uses_only_the_branded_recovery_open_connect_chain() {
    let source = include_str!("conversations.rs");
    let body = source
        .split("pub async fn list_persistent_remote_conversations")
        .nth(1)
        .expect("production conversations adapter");
    let recovery = body
        .find("recovered_paired_machine_store")
        .expect("startup recovery gateway");
    let open = body.find("open_exact").expect("exact machine open");
    let connect = body
        .find("connect_paired_runtime")
        .expect("paired Runtime connector");
    assert!(recovery < open && open < connect);
    for forbidden in ["PairedMachineStore::new", ".key_store()", ".state_root()"] {
        assert!(!body.contains(forbidden));
    }
}
