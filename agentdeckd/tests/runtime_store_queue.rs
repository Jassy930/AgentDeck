use agentdeckd::runtime::store::QueueScope;
use agentdeckd::runtime::store::queue::{QueueAdmission, evaluate_queue_admission};

const MIB: u64 = 1024 * 1024;

#[test]
fn count_limits_are_exact_at_32_and_1024() {
    assert_eq!(
        evaluate_queue_admission(31, 1_023, 0, 1),
        Ok(QueueAdmission { queue_position: 31 })
    );
    assert_eq!(
        evaluate_queue_admission(32, 0, 0, 1),
        Err(QueueScope::Conversation)
    );
    assert_eq!(
        evaluate_queue_admission(0, 1_024, 0, 1),
        Err(QueueScope::GlobalCount)
    );
}

#[test]
fn queued_payload_limit_allows_exact_256_mib_and_rejects_plus_one() {
    let limit = 256 * MIB;
    assert_eq!(
        evaluate_queue_admission(0, 0, limit - 256, 256),
        Ok(QueueAdmission { queue_position: 0 })
    );
    assert_eq!(
        evaluate_queue_admission(0, 0, limit - 255, 256),
        Err(QueueScope::GlobalPayloadBytes)
    );
}

#[test]
fn payload_arithmetic_overflow_fails_closed() {
    assert_eq!(
        evaluate_queue_admission(0, 0, u64::MAX, 1),
        Err(QueueScope::GlobalPayloadBytes)
    );
}
