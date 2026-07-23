#![cfg(unix)]

#[path = "support/remote_pairing.rs"]
#[allow(dead_code)]
mod remote_pairing;

use std::collections::VecDeque;
use std::io::{Cursor, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::sync::{Arc, Mutex};

use agentdeck_cli::remote::keychain::MemoryRemoteKeyStore;
use agentdeck_cli::remote::pair::{
    DurablePairConnection, DurablePairConnector, DurablePairError, DurablePairingCoordinator,
    PairEndpoint, confirm_machine_root_fingerprint, load_pair_invite_from_private_file,
    load_pair_invite_from_reader, mvp_authorization,
};
use agentdeck_cli::remote::pending::PendingPairingCoordinator;
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, PairData, PairRouteCloseOutcome, PairRouteClosed, RouteAccepted, SealedBlob,
    ServerRestarting,
};
use agentdeck_protocol::relay_v2::{PairRouteId, RelayFailure, RelayFrameBody, decode};
use agentdeck_relay_client::{PairingEvent, RelayClientConfig, RelayClientError, RelayTlsPolicy};
use async_trait::async_trait;
use remote_pairing::{DeterministicRng, INSTALLATION_ID, NOW_MS, PairingFixture};

#[derive(Default)]
struct AttemptRecord {
    endpoint_pair_routes: Vec<PairRouteId>,
    sent: Vec<Vec<Vec<u8>>>,
    retry_waits: usize,
}

struct FakeConnection {
    attempt: usize,
    shared: Arc<Mutex<AttemptRecord>>,
    events: VecDeque<Result<Option<PairingEvent>, RelayClientError>>,
}

#[async_trait]
impl DurablePairConnection for FakeConnection {
    async fn send_pair_data_encoded(&mut self, bytes: Vec<u8>) -> Result<(), RelayClientError> {
        let decoded = decode(&bytes).expect("state machine sends canonical Relay v2 bytes");
        let pair_route = self.shared.lock().unwrap().endpoint_pair_routes[self.attempt];
        assert!(matches!(
            decoded.body,
            RelayFrameBody::PairData(ref data) if data.pair_route == pair_route
        ));
        self.shared.lock().unwrap().sent[self.attempt].push(bytes);
        Ok(())
    }

    async fn next_event(&mut self) -> Result<Option<PairingEvent>, RelayClientError> {
        self.events.pop_front().unwrap_or(Ok(None))
    }
}

struct FakeConnector {
    shared: Arc<Mutex<AttemptRecord>>,
    attempts: VecDeque<VecDeque<Result<Option<PairingEvent>, RelayClientError>>>,
}

struct FailingConnector {
    error: RelayClientError,
    connects: usize,
    retry_waits: usize,
}

struct SilentConnection;

#[async_trait]
impl DurablePairConnection for SilentConnection {
    async fn send_pair_data_encoded(&mut self, _bytes: Vec<u8>) -> Result<(), RelayClientError> {
        Ok(())
    }

    async fn next_event(&mut self) -> Result<Option<PairingEvent>, RelayClientError> {
        std::future::pending().await
    }
}

#[derive(Default)]
struct SilentConnector {
    connects: usize,
}

#[async_trait]
impl DurablePairConnector for SilentConnector {
    type Connection = SilentConnection;

    async fn connect(
        &mut self,
        _endpoint: &PairEndpoint,
    ) -> Result<Self::Connection, RelayClientError> {
        self.connects += 1;
        Ok(SilentConnection)
    }

    async fn wait_before_retry(&mut self) {}
}

#[async_trait]
impl DurablePairConnector for FailingConnector {
    type Connection = FakeConnection;

    async fn connect(
        &mut self,
        _endpoint: &PairEndpoint,
    ) -> Result<Self::Connection, RelayClientError> {
        self.connects += 1;
        Err(self.error.clone())
    }

    async fn wait_before_retry(&mut self) {
        self.retry_waits += 1;
    }
}

#[async_trait]
impl DurablePairConnector for FakeConnector {
    type Connection = FakeConnection;

    async fn connect(
        &mut self,
        endpoint: &PairEndpoint,
    ) -> Result<Self::Connection, RelayClientError> {
        let mut shared = self.shared.lock().unwrap();
        let attempt = shared.sent.len();
        shared.endpoint_pair_routes.push(endpoint.pair_route());
        shared.sent.push(Vec::new());
        drop(shared);
        Ok(FakeConnection {
            attempt,
            shared: Arc::clone(&self.shared),
            events: self
                .attempts
                .pop_front()
                .expect("expected reconnect attempt"),
        })
    }

    async fn wait_before_retry(&mut self) {
        self.shared.lock().unwrap().retry_waits += 1;
    }
}

fn event(value: PairingEvent) -> Result<Option<PairingEvent>, RelayClientError> {
    Ok(Some(value))
}

fn data(pair_route: PairRouteId, bytes: Vec<u8>) -> PairingEvent {
    PairingEvent::Data(PairData {
        pair_route,
        sealed_blob: SealedBlob(bytes),
    })
}

fn connector(
    attempts: Vec<Vec<Result<Option<PairingEvent>, RelayClientError>>>,
) -> (FakeConnector, Arc<Mutex<AttemptRecord>>) {
    let shared = Arc::new(Mutex::new(AttemptRecord::default()));
    (
        FakeConnector {
            shared: Arc::clone(&shared),
            attempts: attempts
                .into_iter()
                .map(VecDeque::from)
                .collect::<VecDeque<_>>(),
        },
        shared,
    )
}

fn state_root(path: &Path) -> std::path::PathBuf {
    std::fs::canonicalize(path).unwrap().join("paired")
}

fn sent_carrier(bytes: &[u8]) -> Vec<u8> {
    let frame = decode(bytes).expect("canonical Relay v2 PairData");
    let RelayFrameBody::PairData(data) = frame.body else {
        panic!("expected exact PairData outer frame")
    };
    data.sealed_blob.0
}

#[tokio::test]
async fn unknown_outcome_reconnects_with_exact_request_and_receipt_until_matching_closed() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let pending = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    let mut request_rng = DeterministicRng::new([0x81; 32]);
    let prepared = pending
        .prepare(
            fixture.invite(),
            fixture.authorization(),
            NOW_MS,
            &mut request_rng,
        )
        .unwrap();
    let exact_request = prepared.canonical_request().to_vec();
    let response = fixture.response_for(&prepared, [0x82; 32]);
    drop(prepared);
    let pair_route = fixture.invite().pair_route;
    let accepted = PairingEvent::RouteAccepted(RouteAccepted {
        accepted: AcceptedRef::PairFrame { pair_route },
    });
    let restarting = PairingEvent::ServerRestarting(ServerRestarting {
        drain_deadline_ms: NOW_MS + 1_000,
    });
    let closed = PairingEvent::RouteClosed(PairRouteClosed {
        pair_route,
        outcome: PairRouteCloseOutcome::Closed,
    });
    let (mut connector, shared) = connector(vec![
        vec![
            event(accepted),
            event(data(pair_route, response.clone())),
            event(restarting),
        ],
        vec![event(data(pair_route, response)), event(closed)],
    ]);
    let temp = tempfile::tempdir().unwrap();
    let coordinator =
        DurablePairingCoordinator::new(&store, INSTALLATION_ID, &state_root(temp.path()));
    let mut rng = DeterministicRng::new([0x83; 32]);
    let outcome = coordinator
        .pair(
            fixture.invite().clone(),
            fixture.authorization(),
            &mut connector,
            || NOW_MS + 1,
            &mut rng,
        )
        .await
        .expect("only the matching Closed terminal completes pairing");

    assert_eq!(outcome.pair_route(), pair_route);
    assert_eq!(
        outcome.machine_root_fingerprint().as_bytes(),
        &fixture.invite().machine_root_fingerprint
    );
    assert!(outcome.route_accepted_observed());
    assert!(outcome.recovered_paired_marker());
    let shared = shared.lock().unwrap();
    assert_eq!(shared.endpoint_pair_routes, vec![pair_route, pair_route]);
    assert_eq!(shared.retry_waits, 1);
    assert_eq!(shared.sent.len(), 2);
    assert_eq!(shared.sent[0].len(), 2, "request then canonical receipt");
    assert_eq!(shared.sent[1].len(), 2, "exact retry repeats both carriers");
    assert_eq!(shared.sent[0][0], shared.sent[1][0]);
    assert_eq!(sent_carrier(&shared.sent[0][0]), exact_request);
    assert_eq!(shared.sent[0][1], shared.sent[1][1]);
}

#[tokio::test]
async fn server_restarting_hint_does_not_discard_a_following_closed_terminal() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let pending = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    let mut request_rng = DeterministicRng::new([0x86; 32]);
    let prepared = pending
        .prepare(
            fixture.invite(),
            fixture.authorization(),
            NOW_MS,
            &mut request_rng,
        )
        .unwrap();
    let response = fixture.response_for(&prepared, [0x87; 32]);
    let pair_route = fixture.invite().pair_route;
    let (mut connector, shared) = connector(vec![vec![
        event(data(pair_route, response)),
        event(PairingEvent::ServerRestarting(ServerRestarting {
            drain_deadline_ms: NOW_MS + 1_000,
        })),
        event(PairingEvent::RouteClosed(PairRouteClosed {
            pair_route,
            outcome: PairRouteCloseOutcome::Closed,
        })),
    ]]);
    let temp = tempfile::tempdir().unwrap();
    let coordinator =
        DurablePairingCoordinator::new(&store, INSTALLATION_ID, &state_root(temp.path()));
    let mut rng = DeterministicRng::new([0x88; 32]);

    coordinator
        .pair(
            fixture.invite().clone(),
            fixture.authorization(),
            &mut connector,
            || NOW_MS + 1,
            &mut rng,
        )
        .await
        .expect("drain hint followed by matching Closed is durable success");
    let shared = shared.lock().unwrap();
    assert_eq!(shared.sent.len(), 1);
    assert_eq!(shared.retry_waits, 0);
}

#[tokio::test]
async fn route_accepted_and_eof_are_not_success_and_trigger_exact_request_retry() {
    let fixture = PairingFixture::new();
    let pair_route = fixture.invite().pair_route;
    let (mut connector, shared) = connector(vec![
        vec![
            event(PairingEvent::RouteAccepted(RouteAccepted {
                accepted: AcceptedRef::PairFrame { pair_route },
            })),
            Ok(None),
        ],
        vec![event(PairingEvent::RouteClosed(PairRouteClosed {
            pair_route,
            outcome: PairRouteCloseOutcome::AlreadyAbsent,
        }))],
    ]);
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let coordinator =
        DurablePairingCoordinator::new(&store, INSTALLATION_ID, &state_root(temp.path()));
    let mut rng = DeterministicRng::new([0x91; 32]);
    let error = coordinator
        .pair(
            fixture.invite().clone(),
            fixture.authorization(),
            &mut connector,
            || NOW_MS + 1,
            &mut rng,
        )
        .await
        .expect_err("AlreadyAbsent cannot upgrade RouteAccepted/EOF into success");

    assert!(matches!(error, DurablePairError::OutcomeUnknown));
    let shared = shared.lock().unwrap();
    assert_eq!(shared.sent.len(), 2);
    assert_eq!(shared.sent[0][0], shared.sent[1][0]);
}

#[tokio::test]
async fn transient_relay_failures_before_expiry_retry_until_route_reopens() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let pending = PendingPairingCoordinator::new(&store, INSTALLATION_ID);
    let mut request_rng = DeterministicRng::new([0x96; 32]);
    let prepared = pending
        .prepare(
            fixture.invite(),
            fixture.authorization(),
            NOW_MS,
            &mut request_rng,
        )
        .unwrap();
    let response = fixture.response_for(&prepared, [0x97; 32]);
    let pair_route = fixture.invite().pair_route;
    let (mut connector, shared) = connector(vec![
        vec![event(PairingEvent::Failure(RelayFailure::new(
            "relay.server.draining",
            "server is draining",
        )))],
        vec![event(PairingEvent::Failure(RelayFailure::new(
            "relay.route.not_found",
            "route is being restored",
        )))],
        vec![
            event(data(pair_route, response)),
            event(PairingEvent::RouteClosed(PairRouteClosed {
                pair_route,
                outcome: PairRouteCloseOutcome::Closed,
            })),
        ],
    ]);
    let temp = tempfile::tempdir().unwrap();
    let coordinator =
        DurablePairingCoordinator::new(&store, INSTALLATION_ID, &state_root(temp.path()));
    let mut rng = DeterministicRng::new([0x98; 32]);

    coordinator
        .pair(
            fixture.invite().clone(),
            fixture.authorization(),
            &mut connector,
            || NOW_MS + 1,
            &mut rng,
        )
        .await
        .expect("an unexpired in-memory route may be reopened after Relay restart");

    let shared = shared.lock().unwrap();
    assert_eq!(shared.retry_waits, 2);
    assert_eq!(shared.sent.len(), 3);
    assert_eq!(shared.sent[0][0], shared.sent[1][0]);
    assert_eq!(shared.sent[1][0], shared.sent[2][0]);
}

#[tokio::test]
async fn closed_before_verified_response_and_mismatched_route_are_rejected() {
    for terminal in [
        PairingEvent::RouteClosed(PairRouteClosed {
            pair_route: PairingFixture::new().invite().pair_route,
            outcome: PairRouteCloseOutcome::Closed,
        }),
        PairingEvent::RouteClosed(PairRouteClosed {
            pair_route: PairRouteId::from_bytes([0xee; 16]),
            outcome: PairRouteCloseOutcome::Closed,
        }),
    ] {
        let fixture = PairingFixture::new();
        let (mut connector, _) = connector(vec![vec![event(terminal)]]);
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().unwrap();
        let coordinator =
            DurablePairingCoordinator::new(&store, INSTALLATION_ID, &state_root(temp.path()));
        let mut rng = DeterministicRng::new([0xa1; 32]);
        let error = coordinator
            .pair(
                fixture.invite().clone(),
                fixture.authorization(),
                &mut connector,
                || NOW_MS + 1,
                &mut rng,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            DurablePairError::ClosedBeforeReceipt | DurablePairError::RouteMismatch
        ));
    }
}

#[test]
fn canonical_invite_reader_accepts_one_record_terminator_and_rejects_noncanonical_text() {
    let fixture = PairingFixture::new();
    let uri = fixture.invite().encode_uri(NOW_MS).unwrap();
    let decoded = load_pair_invite_from_reader(Cursor::new(format!("{uri}\n")), NOW_MS).unwrap();
    assert_eq!(decoded, *fixture.invite());

    for invalid in [
        format!(" {uri}\n"),
        format!("{uri}\n\n"),
        format!("{uri}=\n"),
    ] {
        assert!(load_pair_invite_from_reader(Cursor::new(invalid), NOW_MS).is_err());
    }
}

#[test]
fn machine_root_confirmation_is_an_exact_non_echoing_comparison() {
    let fixture = PairingFixture::new();
    let expected = fixture.invite().machine_root_fingerprint_display();
    let confirmed = confirm_machine_root_fingerprint(fixture.invite().clone(), &expected).unwrap();
    let confirmed_debug = format!("{confirmed:?}");
    assert!(confirmed_debug.contains("[REDACTED]"));
    assert!(!confirmed_debug.contains(&expected));

    let error =
        confirm_machine_root_fingerprint(fixture.invite().clone(), &expected.to_ascii_uppercase())
            .unwrap_err();
    assert!(matches!(error, DurablePairError::RootFingerprintMismatch));
    let rendered = format!("{error:?}");
    assert!(!rendered.contains(&expected));
}

#[test]
fn production_authorization_is_the_fixed_full_mvp_allowlist() {
    let authorization = mvp_authorization().unwrap();
    assert_eq!(authorization.device_display_name, "Persistent Remote CLI");
    assert_eq!(authorization, *PairingFixture::new().authorization());
}

#[test]
fn private_invite_file_requires_exact_0600_single_link_and_no_follow() {
    let fixture = PairingFixture::new();
    let uri = fixture.invite().encode_uri(NOW_MS).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let private = directory.path().join("invite.txt");
    let mut file = std::fs::File::create(&private).unwrap();
    writeln!(file, "{uri}").unwrap();
    drop(file);
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        load_pair_invite_from_private_file(&private, NOW_MS).unwrap(),
        *fixture.invite()
    );

    let public = directory.path().join("public.txt");
    std::fs::copy(&private, &public).unwrap();
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_pair_invite_from_private_file(&public, NOW_MS).is_err());

    let link = directory.path().join("invite-link.txt");
    symlink(&private, &link).unwrap();
    assert!(load_pair_invite_from_private_file(&link, NOW_MS).is_err());

    let hardlink = directory.path().join("invite-hardlink.txt");
    std::fs::hard_link(&private, &hardlink).unwrap();
    assert!(load_pair_invite_from_private_file(&private, NOW_MS).is_err());
}

#[tokio::test]
async fn transport_security_failure_is_fatal_without_retry() {
    let fixture = PairingFixture::new();
    let tls = RelayTlsPolicy::pinned_spki(vec![[0x41; 32]]).unwrap();
    let error = RelayClientConfig::new(
        "https://not-wss.example/",
        fixture.invite().relay_server_id,
        tls,
    )
    .expect_err("invalid origin yields a stable security error");
    let mut connector = FailingConnector {
        error,
        connects: 0,
        retry_waits: 0,
    };
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let coordinator =
        DurablePairingCoordinator::new(&store, INSTALLATION_ID, &state_root(temp.path()));
    let mut rng = DeterministicRng::new([0xb1; 32]);
    let error = coordinator
        .pair(
            fixture.invite().clone(),
            fixture.authorization(),
            &mut connector,
            || NOW_MS + 1,
            &mut rng,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, DurablePairError::TransportSecurity(_)));
    assert_eq!(connector.connects, 1);
    assert_eq!(connector.retry_waits, 0);
}

#[tokio::test]
async fn retryable_connect_failure_is_bounded_even_when_clock_does_not_advance() {
    for code in [
        "relay.client.connect_failed",
        "relay.route.not_found",
        "relay.server.draining",
    ] {
        let fixture = PairingFixture::new();
        let mut connector = FailingConnector {
            error: RelayClientError::Failure {
                code: code.to_owned(),
            },
            connects: 0,
            retry_waits: 0,
        };
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().unwrap();
        let coordinator =
            DurablePairingCoordinator::new(&store, INSTALLATION_ID, &state_root(temp.path()));
        let mut rng = DeterministicRng::new([0xc1; 32]);
        let error = coordinator
            .pair(
                fixture.invite().clone(),
                fixture.authorization(),
                &mut connector,
                || NOW_MS + 1,
                &mut rng,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, DurablePairError::OutcomeUnknown));
        assert_eq!(connector.connects, 64, "failure code {code}");
        assert_eq!(connector.retry_waits, 63, "failure code {code}");
    }
}

#[tokio::test]
async fn silent_active_connection_is_bounded_by_the_absolute_invite_deadline() {
    let fixture = PairingFixture::new();
    let mut invite = fixture.invite().clone();
    invite.expires_at_ms = NOW_MS + 1;
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().unwrap();
    let coordinator =
        DurablePairingCoordinator::new(&store, INSTALLATION_ID, &state_root(temp.path()));
    let mut connector = SilentConnector::default();
    let mut rng = DeterministicRng::new([0xc2; 32]);

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        coordinator.pair(
            invite,
            fixture.authorization(),
            &mut connector,
            || NOW_MS,
            &mut rng,
        ),
    )
    .await
    .expect("a silent active connection must not outlive the invite deadline");

    assert!(matches!(result, Err(DurablePairError::OutcomeUnknown)));
    assert_eq!(connector.connects, 64);
}
