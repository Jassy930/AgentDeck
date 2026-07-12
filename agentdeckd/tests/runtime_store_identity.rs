use std::collections::VecDeque;

#[path = "../src/runtime/store/identity.rs"]
mod identity;

use identity::{
    MAX_RUNTIME_ID_COLLISION_ATTEMPTS, OsRuntimeIdSource, RuntimeId, RuntimeIdError, RuntimeIdKind,
    RuntimeIdSource, allocate_unique_runtime_id,
};

struct SequenceIdSource {
    values: VecDeque<[u8; 16]>,
    requested_kinds: Vec<RuntimeIdKind>,
}

impl SequenceIdSource {
    fn new(values: impl IntoIterator<Item = [u8; 16]>) -> Self {
        Self {
            values: values.into_iter().collect(),
            requested_kinds: Vec::new(),
        }
    }
}

impl RuntimeIdSource for SequenceIdSource {
    fn next_id(&mut self, kind: RuntimeIdKind) -> Result<RuntimeId, RuntimeIdError> {
        self.requested_kinds.push(kind);
        RuntimeId::from_bytes(
            kind,
            self.values
                .pop_front()
                .expect("test source has enough candidates"),
        )
    }
}

#[test]
fn bytes_and_canonical_uuid_text_roundtrip_strictly() {
    let bytes = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
        0xfe,
    ];

    for kind in [
        RuntimeIdKind::Database,
        RuntimeIdKind::Conversation,
        RuntimeIdKind::Command,
        RuntimeIdKind::Turn,
        RuntimeIdKind::Event,
        RuntimeIdKind::AdapterState,
        RuntimeIdKind::DaemonBoot,
    ] {
        let id = RuntimeId::from_bytes(kind, bytes).expect("non-zero id");
        assert_eq!(id.kind(), kind);
        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(id.to_string(), "01234567-89ab-cdef-1032-547698badcfe");
        assert_eq!(
            RuntimeId::parse_canonical(kind, &id.to_string()).expect("canonical parse"),
            id
        );
    }
}

#[test]
fn invalid_and_noncanonical_uuid_text_are_distinct_failures() {
    assert!(matches!(
        RuntimeId::parse_canonical(RuntimeIdKind::Command, "not-a-uuid"),
        Err(RuntimeIdError::InvalidText {
            kind: RuntimeIdKind::Command
        })
    ));
    assert!(matches!(
        RuntimeId::parse_canonical(
            RuntimeIdKind::Command,
            "01234567-89AB-CDEF-1032-547698BADCFE"
        ),
        Err(RuntimeIdError::NonCanonicalText {
            kind: RuntimeIdKind::Command
        })
    ));
    assert!(matches!(
        RuntimeId::parse_canonical(RuntimeIdKind::Command, "0123456789abcdef1032547698badcfe"),
        Err(RuntimeIdError::NonCanonicalText {
            kind: RuntimeIdKind::Command
        })
    ));
}

#[test]
fn all_zero_id_is_rejected_from_bytes_and_text() {
    assert!(matches!(
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0; 16]),
        Err(RuntimeIdError::Zero {
            kind: RuntimeIdKind::Conversation
        })
    ));
    assert!(matches!(
        RuntimeId::parse_canonical(
            RuntimeIdKind::Conversation,
            "00000000-0000-0000-0000-000000000000"
        ),
        Err(RuntimeIdError::Zero {
            kind: RuntimeIdKind::Conversation
        })
    ));
}

#[test]
fn operating_system_source_returns_nonzero_128_bit_ids() {
    let mut source = OsRuntimeIdSource;
    let first = source
        .next_id(RuntimeIdKind::Database)
        .expect("OS CSPRNG id");
    let second = source
        .next_id(RuntimeIdKind::Database)
        .expect("second OS CSPRNG id");

    assert_ne!(first.as_bytes(), &[0; 16]);
    assert_ne!(second.as_bytes(), &[0; 16]);
    assert_ne!(first, second);
    assert_eq!(first.to_string().len(), 36);
}

#[test]
fn collision_once_then_success_uses_the_second_candidate() {
    let first = [0x11; 16];
    let second = [0x22; 16];
    let mut source = SequenceIdSource::new([first, second]);
    let mut probes = 0;

    let allocated = allocate_unique_runtime_id(RuntimeIdKind::Event, &mut source, |candidate| {
        probes += 1;
        candidate.as_bytes() == &first
    })
    .expect("second candidate succeeds");

    assert_eq!(allocated.as_bytes(), &second);
    assert_eq!(probes, 2);
    assert_eq!(
        source.requested_kinds,
        [RuntimeIdKind::Event, RuntimeIdKind::Event]
    );
}

#[test]
fn sixteen_collisions_exhaust_without_requesting_a_seventeenth_id() {
    let candidates = (1_u8..=16).map(|value| [value; 16]);
    let mut source = SequenceIdSource::new(candidates);
    let mut probes = 0;

    let error = allocate_unique_runtime_id(RuntimeIdKind::Command, &mut source, |_| {
        probes += 1;
        true
    })
    .expect_err("sixteen collisions exhaust the helper");

    assert_eq!(
        error,
        RuntimeIdError::CollisionExhausted {
            kind: RuntimeIdKind::Command,
            attempts: 16,
        }
    );
    assert_eq!(MAX_RUNTIME_ID_COLLISION_ATTEMPTS, 16);
    assert_eq!(probes, 16);
    assert_eq!(source.requested_kinds.len(), 16);
}
