use agentdeck_crypto::CryptoError;
use agentdeck_crypto::replay::{REPLAY_WINDOW_SIZE, ReplayDisposition, ReplayWindow};
use agentdeck_protocol::e2ee::E2eeError;

fn hash_for(counter: u64) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..8].copy_from_slice(&counter.to_be_bytes());
    hash
}

fn different_hash(mut hash: [u8; 32]) -> [u8; 32] {
    hash[31] ^= 1;
    hash
}

#[test]
fn default_window_starts_empty() {
    let mut window = ReplayWindow::default();
    assert_eq!(window.observe(0, hash_for(0)), Ok(ReplayDisposition::Fresh));
}

#[test]
fn first_observation_is_fresh_and_exact_repeat_is_duplicate() {
    let mut window = ReplayWindow::new();
    let hash = hash_for(7);

    assert_eq!(window.observe(7, hash), Ok(ReplayDisposition::Fresh));
    assert_eq!(
        window.observe(7, hash),
        Ok(ReplayDisposition::ExactDuplicate)
    );
}

#[test]
fn same_counter_with_different_hash_inside_window_is_nonce_reuse() {
    let mut window = ReplayWindow::new();
    let hash = hash_for(42);
    assert_eq!(window.observe(42, hash), Ok(ReplayDisposition::Fresh));

    assert_eq!(
        window.observe(42, different_hash(hash)),
        Err(CryptoError::E2ee(E2eeError::NonceReuse))
    );
}

#[test]
fn window_contains_high_water_and_previous_4095_counters() {
    let mut window = ReplayWindow::new();
    let high_water = 10_000;
    let floor = high_water - (REPLAY_WINDOW_SIZE - 1);

    assert_eq!(
        window.observe(high_water, hash_for(high_water)),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(
        window.observe(floor, hash_for(floor)),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(
        window.observe(floor - 1, hash_for(floor - 1)),
        Ok(ReplayDisposition::Stale)
    );
}

#[test]
fn unseen_out_of_order_counter_inside_window_is_fresh() {
    let mut window = ReplayWindow::new();
    let high_water = REPLAY_WINDOW_SIZE + 100;
    let out_of_order = high_water - 100;

    assert_eq!(
        window.observe(high_water, hash_for(high_water)),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(
        window.observe(out_of_order, hash_for(out_of_order)),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(
        window.observe(out_of_order, hash_for(out_of_order)),
        Ok(ReplayDisposition::ExactDuplicate)
    );
}

#[test]
fn advancing_high_water_evicts_counter_below_new_floor() {
    let mut window = ReplayWindow::new();

    for counter in 0..REPLAY_WINDOW_SIZE {
        assert_eq!(
            window.observe(counter, hash_for(counter)),
            Ok(ReplayDisposition::Fresh)
        );
    }

    assert_eq!(
        window.observe(REPLAY_WINDOW_SIZE, hash_for(REPLAY_WINDOW_SIZE)),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(window.observe(0, hash_for(0)), Ok(ReplayDisposition::Stale));
    assert_eq!(
        window.observe(1, hash_for(1)),
        Ok(ReplayDisposition::ExactDuplicate)
    );
}

#[test]
fn below_floor_is_stale_before_historical_hash_comparison() {
    let mut window = ReplayWindow::new();
    let old_hash = hash_for(0);

    assert_eq!(window.observe(0, old_hash), Ok(ReplayDisposition::Fresh));
    assert_eq!(
        window.observe(REPLAY_WINDOW_SIZE, hash_for(REPLAY_WINDOW_SIZE)),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(
        window.observe(0, different_hash(old_hash)),
        Ok(ReplayDisposition::Stale)
    );
}

#[test]
fn u64_boundary_and_long_sliding_loop_never_panic() {
    let mut window = ReplayWindow::new();

    for counter in 0..(REPLAY_WINDOW_SIZE * 3) {
        assert_eq!(
            window.observe(counter, hash_for(counter)),
            Ok(ReplayDisposition::Fresh)
        );
    }

    let floor_at_max = u64::MAX - (REPLAY_WINDOW_SIZE - 1);
    assert_eq!(
        window.observe(u64::MAX, hash_for(u64::MAX)),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(
        window.observe(floor_at_max, hash_for(floor_at_max)),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(
        window.observe(floor_at_max - 1, hash_for(floor_at_max - 1)),
        Ok(ReplayDisposition::Stale)
    );
    assert_eq!(
        window.observe(u64::MAX, hash_for(u64::MAX)),
        Ok(ReplayDisposition::ExactDuplicate)
    );
}
