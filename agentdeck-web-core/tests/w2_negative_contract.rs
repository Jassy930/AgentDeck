#![cfg(feature = "w2-test-fixture")]

use agentdeck_web_core::w2_negative_snapshot;

#[test]
fn w2_negative_admission_matrix_rejects_without_business_mutation() {
    let snapshot = w2_negative_snapshot();

    assert!(snapshot.approval_loser_recognized_applied);
    assert!(snapshot.approval_loser_zero_claim_mutation);
    assert!(snapshot.stale_publish_rejected);
    assert!(snapshot.skipped_publish_rejected);
    assert!(snapshot.rejected_publish_cursor_unchanged);
    assert!(snapshot.reply_nonce_replay_rejected);
    assert!(snapshot.reply_counter_set_unchanged);
    assert!(snapshot.stream_nonce_reuse_rejected);
    assert!(snapshot.stream_counter_set_unchanged);
    assert!(snapshot.uncommitted_reservation_rejected);
    assert!(snapshot.reservation_overflow_rejected);
    assert!(snapshot.rejected_reservation_counter_unchanged);
}
