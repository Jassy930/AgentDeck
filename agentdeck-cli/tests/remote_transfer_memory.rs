#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_cli::remote::keychain::MemoryRemoteKeyStore;
use agentdeck_cli::remote::paired_machine::{
    PairedMachineStore, PairedMutationObserver, PairedMutationStage,
};
use agentdeck_cli::remote::runtime::{
    ExactRelayFrame, ReceivedRuntimeFrame, RemoteRuntime, RemoteRuntimeError,
    RemoteRuntimeTransport, RemoteRuntimeTransportError, RemoteStreamFrameOutcome,
    RemoteSubscriptionBootstrapItem, RemoteSubscriptionReducer,
};
use agentdeck_cli::remote::transfer_state::{DurableLiveTransferStateV1, DurableTransferOutcomeV1};
use agentdeck_crypto::{AeadSendingKey, SecretAeadKey, SenderCounter, seal_symmetric, sign_sealed};
use agentdeck_protocol::AgentKind;
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyId, KeyPurpose, OuterContextV1, OuterFrameKind, SealedPayloadKind,
    StreamBindingV1,
};
use agentdeck_protocol::relay_v2::frame::{Ack, Publish, SealedBlob};
use agentdeck_protocol::relay_v2::{
    GrantSerial, KeyDirectoryRevision, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody,
    StreamGenerationId, StreamRouteId, TrustEpoch, decode, encode,
};
use agentdeck_protocol::runtime::identity::ConversationId;
use agentdeck_protocol::runtime::{
    CatalogChange, CatalogDelta, ConversationEntry, DurableStreamTransferIdentity, MAX_PART_BYTES,
    MAX_REASSEMBLY_BYTES, MAX_TRANSFER_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor,
    RuntimeStreamItem, RuntimeTransferCarrierV1, RuntimeTransferChannel, StreamCursor,
    TransferEnvelope,
};
use async_trait::async_trait;

use remote_pairing::{
    CATALOG_EPOCH, DeterministicRng, INSTALLATION_ID, KEY_DIRECTORY_REVISION, MACHINE_ROUTE,
    PairingFixture,
};

const CATALOG_STREAM_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x81; 16]);
const CATALOG_STREAM_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x91; 16]);
const MIB: usize = 1024 * 1024;

// 这是 production 路径的额外 live-allocation 门禁，不是 RSS 门禁。阈值明确保留
// paired-state codec/prepared-sidecar 的 bounded 工作集；后续 ownership 优化只能收紧，不能
// 依据一次偶然观测自动放宽。
const CAPACITY_PEAK_GROWTH_LIMIT: usize = 5 * MAX_REASSEMBLY_BYTES as usize;
const COMPLETE_PEAK_GROWTH_LIMIT: usize = 4 * MAX_REASSEMBLY_BYTES as usize;
const DUPLICATE_PEAK_GROWTH_LIMIT: usize = MAX_REASSEMBLY_BYTES as usize / 8;

struct CountingAllocator;

static LIVE_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK_ALLOCATED: AtomicUsize = AtomicUsize::new(0);

fn record_allocation(bytes: usize) {
    let live = LIVE_ALLOCATED.fetch_add(bytes, Ordering::SeqCst) + bytes;
    PEAK_ALLOCATED.fetch_max(live, Ordering::SeqCst);
}

fn record_deallocation(bytes: usize) {
    LIVE_ALLOCATED.fetch_sub(bytes, Ordering::SeqCst);
}

// SAFETY: every operation delegates to `System` with the exact original layout/pointer. The
// atomics only account requested live bytes and never allocate or touch the returned storage.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let allocation = unsafe { System.alloc(layout) };
        if !allocation.is_null() {
            record_allocation(layout.size());
        }
        allocation
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let allocation = unsafe { System.alloc_zeroed(layout) };
        if !allocation.is_null() {
            record_allocation(layout.size());
        }
        allocation
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        record_deallocation(layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let replacement = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            if new_size >= layout.size() {
                record_allocation(new_size - layout.size());
            } else {
                record_deallocation(layout.size() - new_size);
            }
        }
        replacement
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Clone, Copy, Debug)]
struct PeakSample {
    baseline: usize,
    peak: usize,
}

impl PeakSample {
    fn growth(self) -> usize {
        self.peak.saturating_sub(self.baseline)
    }
}

fn measure_peak<R>(operation: impl FnOnce() -> R) -> (R, PeakSample) {
    let baseline = LIVE_ALLOCATED.load(Ordering::SeqCst);
    PEAK_ALLOCATED.store(baseline, Ordering::SeqCst);
    let result = operation();
    let peak = PEAK_ALLOCATED.load(Ordering::SeqCst);
    (result, PeakSample { baseline, peak })
}

struct NoopMutationObserver;

impl PairedMutationObserver for NoopMutationObserver {
    fn after_stage(&self, _stage: PairedMutationStage) {}
}

struct AckFailureTransport {
    inbound: VecDeque<ReceivedRuntimeFrame>,
    ack_attempts: Arc<AtomicUsize>,
    fail_first_ack: bool,
}

impl AckFailureTransport {
    fn new(frames: Vec<OpaqueRouteFrame>, fail_first_ack: bool) -> (Self, Arc<AtomicUsize>) {
        let ack_attempts = Arc::new(AtomicUsize::new(0));
        (
            Self {
                inbound: frames.into_iter().map(received_exact).collect(),
                ack_attempts: Arc::clone(&ack_attempts),
                fail_first_ack,
            },
            ack_attempts,
        )
    }
}

#[async_trait]
impl RemoteRuntimeTransport for AckFailureTransport {
    async fn send(&mut self, frame: ExactRelayFrame) -> Result<(), RemoteRuntimeTransportError> {
        let bytes = frame.into_bytes();
        let decoded = decode(&bytes).expect("Runtime memory gate only receives canonical ACKs");
        assert!(matches!(decoded.body, RelayFrameBody::Ack(Ack { .. })));
        self.ack_attempts.fetch_add(1, Ordering::SeqCst);
        if self.fail_first_ack {
            self.fail_first_ack = false;
            return Err(RemoteRuntimeTransportError::Failed(
                "injected transfer ACK failure".to_owned(),
            ));
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RemoteRuntimeTransportError> {
        Ok(self.inbound.pop_front())
    }
}

#[derive(Clone)]
struct LeanCatalogReducer {
    cursor: RuntimeInnerCursor,
    applied: usize,
}

impl LeanCatalogReducer {
    fn new(cursor: StreamCursor) -> Self {
        Self {
            cursor: RuntimeInnerCursor::Catalog { cursor },
            applied: 0,
        }
    }
}

impl RemoteSubscriptionReducer for LeanCatalogReducer {
    const MAX_RETAINED_BYTES: usize = std::mem::size_of::<Self>();

    fn inner_cursor(&self) -> &RuntimeInnerCursor {
        &self.cursor
    }

    fn apply(&mut self, _item: &RemoteSubscriptionBootstrapItem) -> Result<(), RemoteRuntimeError> {
        Err(RemoteRuntimeError::InvalidReply(
            "memory gate reducer does not accept bootstrap items",
        ))
    }

    fn apply_live(&mut self, item: &RuntimeStreamItem) -> Result<(), RemoteRuntimeError> {
        let RuntimeStreamItem::CatalogDelta(delta) = item else {
            return Err(RemoteRuntimeError::InvalidReply(
                "memory gate reducer expected a CatalogDelta",
            ));
        };
        let RuntimeInnerCursor::Catalog { cursor } = self.cursor else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        if cursor.checked_next().ok() != Some(delta.catalog_revision) {
            return Err(RemoteRuntimeError::InvalidReply(
                "memory gate reducer received a non-contiguous CatalogDelta",
            ));
        }
        self.cursor = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(delta.catalog_revision),
        };
        self.applied += 1;
        Ok(())
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("wall clock must be after the Unix epoch")
            .as_millis(),
    )
    .expect("current epoch milliseconds fit u64")
}

fn catalog_binding(fixture: &PairingFixture, inner: StreamCursor) -> StreamBindingV1 {
    StreamBindingV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: fixture.machine_route(),
        device_route: fixture.device_route(),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
        stream_route: CATALOG_STREAM_ROUTE,
        stream_generation: CATALOG_STREAM_GENERATION,
        stream_cursor: StreamCursor::BeforeFirst,
        inner_cursor: RuntimeInnerCursor::Catalog { cursor: inner },
        key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: CATALOG_EPOCH,
        },
    }
}

fn carrier(
    identity: DurableStreamTransferIdentity,
    part_index: u32,
    part: Vec<u8>,
) -> RuntimeTransferCarrierV1 {
    RuntimeTransferCarrierV1::new(
        identity.message_id(),
        RuntimeTransferChannel::Stream,
        TransferEnvelope::new(
            identity.transfer_id(),
            part_index,
            identity.part_count(),
            identity.total_sha256(),
            identity.total_bytes(),
            part,
        )
        .expect("memory gate transfer part is representable"),
    )
}

fn push_incomplete_part(
    state: DurableLiveTransferStateV1,
    binding: &StreamBindingV1,
    identity: DurableStreamTransferIdentity,
    part_index: u32,
    part: Vec<u8>,
    now_ms: u64,
) -> DurableLiveTransferStateV1 {
    let transition = state
        .accept_part(binding, carrier(identity, part_index, part), now_ms)
        .expect("memory gate preseed part is valid");
    assert!(matches!(
        transition.outcome(),
        DurableTransferOutcomeV1::Buffered { .. }
    ));
    transition.into_state()
}

fn transfer_publish_frame(
    stream_seq: u64,
    sender_counter: u64,
    carrier: RuntimeTransferCarrierV1,
) -> OpaqueRouteFrame {
    let context = OuterContextV1 {
        frame_kind: OuterFrameKind::CatalogPublish,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(MACHINE_ROUTE),
        device_route: None,
        stream_route: Some(CATALOG_STREAM_ROUTE),
        request_route: None,
        pair_route: None,
        stream_generation: Some(CATALOG_STREAM_GENERATION),
        stream_cursor: None,
        stream_seq: Some(stream_seq),
        message_key_epoch: CATALOG_EPOCH,
    };
    let key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: CATALOG_EPOCH,
        },
        CATALOG_EPOCH,
        KEY_DIRECTORY_REVISION,
        SecretAeadKey::from_bytes([0x71; 32]),
    );
    let unsigned = seal_symmetric(
        &key,
        &context,
        SealedPayloadKind::TransferPart,
        &carrier.encode().expect("canonical transfer carrier"),
        SenderCounter(sender_counter),
    )
    .expect("seal memory gate transfer part");
    let signed = sign_sealed(
        unsigned,
        &PairingFixture::machine_data_signing_key(),
        &context,
    );
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Publish(Publish {
            stream_route: CATALOG_STREAM_ROUTE,
            generation: CATALOG_STREAM_GENERATION,
            stream_seq,
            sealed_blob: SealedBlob(signed.to_wire_bytes()),
        }),
    }
}

fn received_exact(frame: OpaqueRouteFrame) -> ReceivedRuntimeFrame {
    let canonical = encode(&frame);
    ReceivedRuntimeFrame::from_untrusted_parts(frame, canonical)
}

fn exact_max_catalog_payload(revision: u64) -> Vec<u8> {
    let make_delta = |title: String| CatalogDelta {
        catalog_revision: revision,
        changes: vec![CatalogChange::Upserted {
            entry: ConversationEntry {
                conversation_id: ConversationId::new("018f0f9d-6f0a-7ad0-8000-0000000000a1"),
                agent_kind: AgentKind::Codex,
                title: Some(title),
                cwd: Some(PathBuf::from("/tmp/remote-transfer-memory")),
                last_active_ms: 101,
                archived: false,
                entry_revision: revision,
            },
        }],
    };
    let empty = serde_json::to_vec(&make_delta(String::new())).expect("encode empty delta");
    let target = usize::try_from(MAX_TRANSFER_BYTES).expect("64 MiB fits usize");
    let filler = target
        .checked_sub(empty.len())
        .expect("CatalogDelta envelope is smaller than transfer maximum");
    let payload = serde_json::to_vec(&make_delta("x".repeat(filler)))
        .expect("encode exact-limit CatalogDelta");
    assert_eq!(payload.len(), target);
    payload
}

fn capacity_to_marker_peak(tokio: &tokio::runtime::Runtime) -> PeakSample {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("capacity memory gate root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical capacity memory gate root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0x91);
    let observer = Arc::new(NoopMutationObserver);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        observer.clone(),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open capacity memory gate machine");
    let binding = catalog_binding(&fixture, StreamCursor::BeforeFirst);
    let mut rng = DeterministicRng::new([0x92; 32]);
    let installed = opened
        .install_stream_binding_for_automatic_harness(binding.clone(), &mut rng)
        .expect("install capacity memory gate binding");

    let empty = DurableLiveTransferStateV1::empty();
    let mut near_limit = empty.clone();
    let mut clock = now_ms();
    for (revision, digest, fill) in [(101, [0xa1; 32], 0xa1), (102, [0xa2; 32], 0xa2)] {
        let identity = DurableStreamTransferIdentity::from_catalog_metadata(
            revision,
            revision,
            MAX_TRANSFER_BYTES,
            digest,
        )
        .expect("capacity preseed identity");
        for part_index in 0..17 {
            near_limit = push_incomplete_part(
                near_limit,
                &binding,
                identity,
                part_index,
                vec![fill; MAX_PART_BYTES],
                clock,
            );
            clock += 1;
        }
    }
    let tail_identity = DurableStreamTransferIdentity::from_catalog_metadata(
        103,
        103,
        MAX_TRANSFER_BYTES,
        [0xa3; 32],
    )
    .expect("capacity tail identity");
    near_limit = push_incomplete_part(
        near_limit,
        &binding,
        tail_identity,
        0,
        vec![0xa3; MIB],
        clock,
    );
    // 120 MiB stays below the production normal-state limit after reserving the
    // per-binding replay+marker emergency headroom. The next maximum-sized part
    // crosses that normal limit while remaining below the 128 MiB hard cap, so
    // production must consume the reserved marker path instead of rejecting the
    // already-durable base state as over-capacity.
    assert_eq!(near_limit.buffered_bytes(), 120 * MIB as u64);
    let mut persist_rng = DeterministicRng::new([0x93; 32]);
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &installed,
            &installed,
            &empty,
            &near_limit,
            &mut persist_rng,
        )
        .expect("persist 120 MiB production precondition");
    drop(near_limit);
    drop(opened);

    let incoming = transfer_publish_frame(
        0,
        901,
        carrier(tail_identity, 1, vec![0xb3; MAX_PART_BYTES]),
    );
    let (transport, ack_attempts) = AckFailureTransport::new(vec![incoming], false);
    // AutomaticHarness 只负责构造大状态。真正被计量的 handle 必须重新由 production
    // constructor mint，避免把 test-only runtime-state authority 混入 production gate。
    let production = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let opened = production
        .open_exact(fixture.identity())
        .expect("reopen capacity production ingress");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = LeanCatalogReducer::new(StreamCursor::BeforeFirst);

    let (result, sample) =
        measure_peak(|| tokio.block_on(runtime.receive_stream_frame(&mut reducer)));
    assert_eq!(
        result
            .expect_err("over-normal paired candidate must become a durable marker")
            .code(),
        "remote.transfer.reassembly_full",
    );
    assert_eq!(ack_attempts.load(Ordering::SeqCst), 0);
    assert_eq!(reducer.applied, 0);
    drop(runtime);

    let reopened = production
        .open_exact(fixture.identity())
        .expect("read back capacity marker");
    let transfer = reopened
        .durable_transfer_state()
        .expect("read durable capacity marker state");
    assert_eq!(transfer.active_count(), 0);
    assert_eq!(transfer.completed_count(), 0);
    assert_eq!(transfer.marker_count(), 1);
    assert_eq!(transfer.buffered_bytes(), 0);
    sample
}

fn complete_ack_failure_and_duplicate_peaks(
    tokio: &tokio::runtime::Runtime,
) -> (PeakSample, PeakSample) {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("complete memory gate root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical complete memory gate root")
        .join("paired-state");
    fixture.promote(&store, &state_root, 0xa1);
    let observer = Arc::new(NoopMutationObserver);
    let paired = PairedMachineStore::new_with_mutation_observer(
        &store,
        INSTALLATION_ID,
        &state_root,
        observer.clone(),
    );
    let mut opened = paired
        .open_exact(fixture.identity())
        .expect("open complete memory gate machine");
    let previous_revision = 40;
    let revision = previous_revision + 1;
    let binding = catalog_binding(&fixture, StreamCursor::At(previous_revision));
    let mut rng = DeterministicRng::new([0xa2; 32]);
    let installed = opened
        .install_stream_binding_for_automatic_harness(binding.clone(), &mut rng)
        .expect("install complete memory gate binding");

    let payload = exact_max_catalog_payload(revision);
    let identity = DurableStreamTransferIdentity::for_catalog(revision, revision, &payload)
        .expect("exact 64 MiB transfer identity");
    assert_eq!(identity.part_count(), 19);
    let empty = DurableLiveTransferStateV1::empty();
    let mut active = empty.clone();
    let clock = now_ms();
    for part_index in 0..18_u32 {
        let start = part_index as usize * MAX_PART_BYTES;
        let end = start + MAX_PART_BYTES;
        active = push_incomplete_part(
            active,
            &binding,
            identity,
            part_index,
            payload[start..end].to_vec(),
            clock + u64::from(part_index),
        );
    }
    assert_eq!(active.buffered_bytes(), 63 * MIB as u64);
    let final_start = 18 * MAX_PART_BYTES;
    let final_frame = transfer_publish_frame(
        0,
        1_001,
        carrier(identity, 18, payload[final_start..].to_vec()),
    );
    drop(payload);
    let mut persist_rng = DeterministicRng::new([0xa3; 32]);
    opened
        .commit_stream_transfer_transition_for_automatic_harness(
            &installed,
            &installed,
            &empty,
            &active,
            &mut persist_rng,
        )
        .expect("persist 63 MiB production precondition");
    drop(active);
    drop(opened);

    let (transport, ack_attempts) =
        AckFailureTransport::new(vec![final_frame.clone(), final_frame], true);
    let production = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let opened = production
        .open_exact(fixture.identity())
        .expect("reopen complete production ingress");
    let mut runtime = RemoteRuntime::new(opened, transport);
    let mut reducer = LeanCatalogReducer::new(StreamCursor::At(previous_revision));

    let (first, complete_sample) =
        measure_peak(|| tokio.block_on(runtime.receive_stream_frame(&mut reducer)));
    assert_eq!(
        first
            .expect_err("first cumulative ACK must fail after durable completion")
            .code(),
        "remote.runtime.transport_failed",
    );
    assert_eq!(ack_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(reducer.applied, 1);
    assert_eq!(
        reducer.inner_cursor(),
        &RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(revision),
        }
    );

    let (duplicate, duplicate_sample) =
        measure_peak(|| tokio.block_on(runtime.receive_stream_frame(&mut reducer)));
    assert!(matches!(
        duplicate,
        Ok(RemoteStreamFrameOutcome::AppliedDuplicate)
    ));
    assert_eq!(ack_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        reducer.applied, 1,
        "exact duplicate must not re-enter reducer"
    );
    drop(runtime);

    let reopened = production
        .open_exact(fixture.identity())
        .expect("read back completed transfer");
    let transfer = reopened
        .durable_transfer_state()
        .expect("read durable completed transfer state");
    assert_eq!(transfer.active_count(), 0);
    assert_eq!(transfer.completed_count(), 1);
    assert_eq!(transfer.marker_count(), 0);
    assert_eq!(transfer.buffered_bytes(), 0);
    let bindings = reopened
        .durable_stream_bindings()
        .expect("read completed transfer binding");
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].outer_applied(), StreamCursor::At(0));
    assert_eq!(bindings[0].outer_acked(), StreamCursor::At(0));
    assert_eq!(
        bindings[0].inner_applied(),
        &RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(revision),
        }
    );
    (complete_sample, duplicate_sample)
}

#[test]
#[ignore = "large production allocation gate; run explicitly in the P4.6 release gate"]
fn production_transfer_peak_is_bounded_across_capacity_completion_and_duplicate() {
    // 本 integration binary 只有这一个 test；current-thread Tokio 又避免 worker 噪声。因此
    // 全局 allocator 不会与同进程并行 case 争用，Cargo 并行的其他 integration binaries 也在
    // 独立进程中。仍固定 `--test-threads=1`，防止未来向本文件追加测试后悄然破坏采样。
    let tokio = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("build current-thread Runtime");
    let capacity = capacity_to_marker_peak(&tokio);
    eprintln!(
        "remote transfer capacity peak growth: {} MiB",
        capacity.growth() / MIB,
    );
    assert!(
        capacity.growth() <= CAPACITY_PEAK_GROWTH_LIMIT,
        "capacity→marker additional allocation peak {} exceeds {} bytes (baseline={}, peak={})",
        capacity.growth(),
        CAPACITY_PEAK_GROWTH_LIMIT,
        capacity.baseline,
        capacity.peak,
    );
    let (complete, duplicate) = complete_ack_failure_and_duplicate_peaks(&tokio);

    eprintln!(
        "remote transfer peak growth: capacity={} MiB complete={} MiB duplicate={} MiB",
        capacity.growth() / MIB,
        complete.growth() / MIB,
        duplicate.growth() / MIB,
    );
    assert!(
        complete.growth() <= COMPLETE_PEAK_GROWTH_LIMIT,
        "64 MiB complete additional allocation peak {} exceeds {} bytes (baseline={}, peak={})",
        complete.growth(),
        COMPLETE_PEAK_GROWTH_LIMIT,
        complete.baseline,
        complete.peak,
    );
    assert!(
        duplicate.growth() <= DUPLICATE_PEAK_GROWTH_LIMIT,
        "exact duplicate additional allocation peak {} exceeds {} bytes (baseline={}, peak={})",
        duplicate.growth(),
        DUPLICATE_PEAK_GROWTH_LIMIT,
        duplicate.baseline,
        duplicate.peak,
    );
    assert!(
        u64::try_from(COMPLETE_PEAK_GROWTH_LIMIT).unwrap() <= 4 * MAX_REASSEMBLY_BYTES,
        "the complete-path gate must stay tied to the protocol memory scale",
    );
}
