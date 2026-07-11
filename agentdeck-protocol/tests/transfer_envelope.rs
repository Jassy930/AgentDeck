//! P1.1 TransferEnvelope 契约 + 纯重组器状态机（design §9.5）。
//!
//! `TransferEnvelope { transferId, partIndex, partCount, totalSha256, totalBytes, part }`
//! - part ≤ 3.5 MiB，单 transfer ≤ 64 parts / 64 MiB，TTL 5 分钟。
//! - 首 part 后 partCount/totalBytes/hash 不可变。
//! - 每 connection 重组 ≤ 128 MiB；重复 index 不同内容 / hash 不符 / 超时 → typed error。
//!
//! 重组器无 IO、时间由调用方注入（now_ms）。

use agentdeck_protocol::runtime::identity::TransferId;
use agentdeck_protocol::runtime::transfer::{
    MAX_PART_BYTES, MAX_REASSEMBLY_BYTES, MAX_TRANSFER_BYTES, MAX_TRANSFER_PARTS, TRANSFER_TTL_MS,
    TransferEnvelope, TransferProgress, TransferReassembler,
};
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// 把 payload 均匀切成 `part_count` 个 part（最后一段可短）。
fn split(payload: &[u8], part_count: u32) -> Vec<TransferEnvelope> {
    let hash = sha256(payload);
    let total = payload.len() as u64;
    let chunk = (payload.len() as u32).div_ceil(part_count.max(1)) as usize;
    let mut out = Vec::new();
    for i in 0..part_count {
        let start = (i as usize) * chunk;
        let end = ((i as usize + 1) * chunk).min(payload.len());
        let slice = if start <= payload.len() {
            &payload[start..end]
        } else {
            &[]
        };
        out.push(
            TransferEnvelope::new(
                TransferId::new("t1"),
                i,
                part_count,
                hash,
                total,
                slice.to_vec(),
            )
            .unwrap(),
        );
    }
    out
}

#[test]
fn limit_constants_match_design() {
    assert_eq!(MAX_PART_BYTES, 3_670_016); // 3.5 MiB
    assert_eq!(MAX_TRANSFER_PARTS, 64);
    assert_eq!(MAX_TRANSFER_BYTES, 64 * 1024 * 1024);
    assert_eq!(MAX_REASSEMBLY_BYTES, 128 * 1024 * 1024);
    assert_eq!(TRANSFER_TTL_MS, 5 * 60 * 1000);
}

#[test]
fn single_part_transfer_completes() {
    let payload = b"hello world".to_vec();
    let mut r = TransferReassembler::new();
    let parts = split(&payload, 1);
    match r.accept(parts[0].clone(), 0).unwrap() {
        TransferProgress::Complete(bytes) => assert_eq!(bytes, payload),
        other => panic!("expected complete, got {other:?}"),
    }
}

#[test]
fn sixty_four_parts_reassemble_out_of_order() {
    let payload: Vec<u8> = (0..64u32).flat_map(|i| vec![i as u8; 100]).collect();
    let parts = split(&payload, MAX_TRANSFER_PARTS);
    assert_eq!(parts.len(), 64);
    let mut r = TransferReassembler::new();
    // feed in reverse order
    let mut done = None;
    for env in parts.into_iter().rev() {
        match r.accept(env, 10).unwrap() {
            TransferProgress::Complete(bytes) => done = Some(bytes),
            TransferProgress::InProgress { .. } => {}
        }
    }
    assert_eq!(done.unwrap(), payload);
}

#[test]
fn sixty_five_parts_rejected_at_construction() {
    let err = TransferEnvelope::new(TransferId::new("t1"), 0, 65, [0u8; 32], 10, vec![0u8; 10])
        .unwrap_err();
    assert_eq!(err.code(), "remote.transfer.too_large");
}

#[test]
fn oversize_part_rejected_at_construction() {
    let err = TransferEnvelope::new(
        TransferId::new("t1"),
        0,
        1,
        [0u8; 32],
        (MAX_PART_BYTES + 1) as u64,
        vec![0u8; MAX_PART_BYTES + 1],
    )
    .unwrap_err();
    assert_eq!(err.code(), "remote.transfer.too_large");
}

#[test]
fn oversize_total_rejected_at_construction() {
    let err = TransferEnvelope::new(
        TransferId::new("t1"),
        0,
        1,
        [0u8; 32],
        MAX_TRANSFER_BYTES + 1,
        vec![0u8; 10],
    )
    .unwrap_err();
    assert_eq!(err.code(), "remote.transfer.too_large");
}

#[test]
fn part_index_out_of_range_rejected() {
    let err = TransferEnvelope::new(TransferId::new("t1"), 3, 3, [0u8; 32], 10, vec![0u8; 10])
        .unwrap_err();
    assert_eq!(err.code(), "remote.transfer.too_large");
}

#[test]
fn duplicate_same_part_is_idempotent() {
    let payload = vec![7u8; 300];
    let parts = split(&payload, 3);
    let mut r = TransferReassembler::new();
    r.accept(parts[0].clone(), 0).unwrap();
    // re-send part 0 verbatim → idempotent, no error, still in progress
    match r.accept(parts[0].clone(), 0).unwrap() {
        TransferProgress::InProgress {
            received_parts,
            part_count,
        } => {
            assert_eq!(received_parts, 1);
            assert_eq!(part_count, 3);
        }
        other => panic!("expected in-progress, got {other:?}"),
    }
}

#[test]
fn duplicate_index_conflicting_content_errors() {
    let payload = vec![1u8; 300];
    let parts = split(&payload, 3);
    let mut r = TransferReassembler::new();
    r.accept(parts[0].clone(), 0).unwrap();
    // same transferId/index but different bytes → conflict
    let conflict = TransferEnvelope::new(
        parts[0].transfer_id.clone(),
        0,
        3,
        parts[0].total_sha256,
        parts[0].total_bytes,
        vec![9u8; parts[0].part.len()],
    )
    .unwrap();
    let err = r.accept(conflict, 0).unwrap_err();
    assert_eq!(err.code(), "remote.transfer.hash_mismatch");
}

#[test]
fn changed_metadata_after_first_part_errors() {
    let payload = vec![1u8; 300];
    let parts = split(&payload, 3);
    let mut r = TransferReassembler::new();
    r.accept(parts[0].clone(), 0).unwrap();
    // part 1 claims a different partCount → metadata changed
    let bad = TransferEnvelope::new(
        parts[1].transfer_id.clone(),
        1,
        4, // different part_count
        parts[1].total_sha256,
        parts[1].total_bytes,
        parts[1].part.clone(),
    )
    .unwrap();
    let err = r.accept(bad, 0).unwrap_err();
    assert_eq!(err.code(), "remote.transfer.hash_mismatch");
}

#[test]
fn wrong_total_hash_detected_on_completion() {
    let payload = vec![5u8; 200];
    let real_hash = sha256(&payload);
    let wrong_hash = {
        let mut h = real_hash;
        h[0] ^= 0xFF;
        h
    };
    // single part but committed hash does not match payload
    let env = TransferEnvelope::new(
        TransferId::new("t1"),
        0,
        1,
        wrong_hash,
        payload.len() as u64,
        payload.clone(),
    )
    .unwrap();
    let mut r = TransferReassembler::new();
    let err = r.accept(env, 0).unwrap_err();
    assert_eq!(err.code(), "remote.transfer.hash_mismatch");
}

#[test]
fn ttl_expiry_aborts_transfer() {
    let payload = vec![3u8; 300];
    let parts = split(&payload, 3);
    let mut r = TransferReassembler::new();
    r.accept(parts[0].clone(), 1_000).unwrap();
    // part 1 arrives after TTL window
    let err = r
        .accept(parts[1].clone(), 1_000 + TRANSFER_TTL_MS + 1)
        .unwrap_err();
    assert_eq!(err.code(), "remote.transfer.expired");
}

#[test]
fn reassembly_cap_enforced_across_transfers() {
    // 用小上限验证纯状态机的 128 MiB 语义（无需真的分配 128 MiB）。
    let mut r = TransferReassembler::with_limits(500, TRANSFER_TTL_MS);
    // t1：600 字节切 2 片（每片 300）；只喂首片 → 保持 in-progress，占用 300。
    let payload_a = vec![1u8; 600];
    let a = split(&payload_a, 2);
    assert_eq!(a[0].part.len(), 300);
    r.accept(a[0].clone(), 0).unwrap();

    // t2：另一个 transfer 的首片 250 字节。
    let payload_b = vec![2u8; 500];
    let hash_b = sha256(&payload_b);
    let b0 =
        TransferEnvelope::new(TransferId::new("t2"), 0, 2, hash_b, 500, vec![2u8; 250]).unwrap();
    // 300 (t1) + 250 (t2) = 550 > 500 cap
    let err = r.accept(b0, 0).unwrap_err();
    assert_eq!(err.code(), "remote.transfer.reassembly_full");
}

#[test]
fn envelope_round_trips_with_base64_wire() {
    let env = TransferEnvelope::new(
        TransferId::new("t1"),
        0,
        1,
        [0xAB; 32],
        4,
        vec![0xDE, 0xAD, 0xBE, 0xEF],
    )
    .unwrap();
    let json = serde_json::to_value(&env).unwrap();
    // part 与 hash 走 base64 字符串，不是 JSON 数字数组
    assert!(json["part"].is_string());
    assert!(json["totalSha256"].is_string());
    let back: TransferEnvelope = serde_json::from_value(json).unwrap();
    assert_eq!(back, env);
}
