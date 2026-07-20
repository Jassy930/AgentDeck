use std::fs;
use std::path::PathBuf;

fn source(path: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn pairing_store_authority_stays_inside_agentdeckd() {
    let pairing = source("src/runtime/store/pairing.rs");
    for declaration in [
        "pub(crate) struct PreparePairingInvite",
        "pub(crate) struct AcceptPairRequest",
        "pub(crate) struct CommitPairPending",
        "pub(crate) struct PairPendingPreparation",
        "pub(crate) enum PairingInviteLifecycle",
        "pub(crate) struct PairingInviteRecord",
        "pub(crate) enum PreparePairingInviteOutcome",
        "pub(crate) enum AcceptPairRequestOutcome",
        "pub(crate) enum CommitPairPendingOutcome",
        "pub(crate) struct AcknowledgePairRouteOpenOutcome",
        "pub(crate) fn canonical_invite(&self)",
        "pub(crate) fn into_invite_hpke_private_key(",
        "pub(crate) fn pair_pending_preparation(",
        "pub(crate) const fn recipient(&self) -> &HpkePublicKey",
    ] {
        assert!(
            pairing.contains(declaration),
            "missing boundary: {declaration}"
        );
    }
    assert!(!pairing.contains("fn invite_hpke_private_key(&self) -> &[u8]"));
    assert!(!pairing.contains("pub(crate) fn canonical_pair_request_plaintext"));
    assert!(!pairing.contains("pub(crate) fn invite_secret"));

    let store = source("src/runtime/store/mod.rs");
    assert!(!store.contains("pub use pairing::{"));
    assert!(!store.contains("pub(crate) use pairing::{"));

    let worker = source("src/runtime/store/worker.rs");
    for method in [
        "pub(crate) async fn prepare_pairing_invite(",
        "pub(crate) async fn acknowledge_pair_route_open(",
        "pub(crate) async fn accept_pair_request(",
        "pub(crate) async fn replay_pair_request(",
        "pub(crate) async fn commit_pair_pending(",
        "pub(crate) async fn load_pairing_invite(",
        "pub(crate) async fn list_pairing_recovery(",
        "pub(crate) async fn list_pending_pairings(",
    ] {
        assert!(worker.contains(method), "missing boundary: {method}");
        assert!(!worker.contains(&method.replacen("pub(crate)", "pub", 1)));
    }
    let prepare = worker
        .split_once("pub(crate) async fn prepare_pairing_invite(")
        .expect("prepare method")
        .1
        .split_once("pub(crate) async fn acknowledge_pair_route_open(")
        .expect("prepare method boundary")
        .0;
    for normal_lane_binding in [
        "&self.normal_tx",
        "&self.normal_budget",
        "RuntimeStoreLane::Normal",
        "NormalCommand::PreparePairingInvite",
    ] {
        assert!(prepare.contains(normal_lane_binding));
    }
    assert!(!prepare.contains("SafetyCommand::PreparePairingInvite"));

    let accept = worker
        .split_once("pub(crate) async fn accept_pair_request(")
        .expect("accept method")
        .1
        .split_once("pub(crate) async fn commit_pair_pending(")
        .expect("accept method boundary")
        .0;
    let pending = worker
        .split_once("pub(crate) async fn commit_pair_pending(")
        .expect("pending method")
        .1
        .split_once("pub(crate) async fn load_pairing_invite(")
        .expect("pending method boundary")
        .0;
    for safety in [
        (accept, "SafetyCommand::AcceptPairRequest"),
        (pending, "SafetyCommand::CommitPairPending"),
    ] {
        assert!(safety.0.contains("&self.safety_tx"));
        assert!(safety.0.contains("&self.safety_budget"));
        assert!(safety.0.contains("RuntimeStoreLane::Safety"));
        assert!(safety.0.contains(safety.1));
    }

    let replay = worker
        .split_once("pub(crate) async fn replay_pair_request(")
        .expect("replay method")
        .1
        .split_once("pub(crate) async fn list_pairing_recovery(")
        .expect("replay method boundary")
        .0;
    assert!(replay.contains("&self.read_tx"));
    assert!(replay.contains("RuntimeStoreLane::Read"));
    assert!(replay.contains("ReadCommand::ReplayPairRequest"));
}
