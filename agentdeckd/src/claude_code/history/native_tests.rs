use std::collections::HashSet;
use std::ffi::CString;
use std::io::{BufReader, Cursor};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::native::{
    NativeHistoryError, NativeHistorySource, NativeIoBudget, NativeParseLimits, NativeReadOutcome,
    NativeScanStep, NativeScanStop, NativeTailState, NativeTranscriptRefV1, parse_native_jsonl,
};

const USER_UUID: &str = "10000000-0000-4000-8000-000000000001";
const THINK_UUID: &str = "20000000-0000-4000-8000-000000000002";
const TEXT_UUID: &str = "30000000-0000-4000-8000-000000000003";
const TOOL_UUID: &str = "40000000-0000-4000-8000-000000000004";
const RESULT_UUID: &str = "50000000-0000-4000-8000-000000000005";
const SECOND_UUID: &str = "60000000-0000-4000-8000-000000000006";
const TOOL_ID: &str = "toolu_native_history_fixture";

#[cfg(unix)]
#[test]
fn native_current_account_root_ignores_poisoned_home_in_child_process() {
    const CHILD: &str = "AGENTDECK_NATIVE_HOME_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let expected = crate::config::current_user_home()
            .expect("OS account home")
            .join(".claude")
            .join("projects");
        assert_eq!(
            super::native::current_projects_path().expect("native projects path"),
            expected
        );
        assert_ne!(expected, PathBuf::from("/tmp/agentdeck-poison-home"));
        return;
    }

    let status = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg(
            "claude_code::history::native_tests::native_current_account_root_ignores_poisoned_home_in_child_process",
        )
        .arg("--nocapture")
        .env(CHILD, "1")
        .env("HOME", "/tmp/agentdeck-poison-home")
        .status()
        .expect("run isolated HOME child");
    assert!(status.success(), "isolated HOME child must pass");
}

#[cfg(unix)]
#[test]
fn native_source_accepts_current_uid_0644_without_exact_mode_gate() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = NativeFixture::new();
    let file = fixture.write_transcript("-tmp-native-a", USER_UUID, &one_user_line(USER_UUID));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(
        file.parent().unwrap(),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    let source = fixture.source();
    let candidate = first_candidate(&source);
    let outcome = source
        .read(
            candidate.reference(),
            &mut generous_budget(),
            NativeParseLimits::default(),
        )
        .expect("current-UID 0644 transcript must be accepted");
    let NativeReadOutcome::Document(document) = outcome else {
        panic!("normal transcript must not be filtered");
    };
    assert_eq!(document.turns().len(), 1);
}

#[test]
fn native_projection_read_preserves_keys_and_applies_fixed_bounds() {
    let fixture = NativeFixture::new();
    let transcript = full_turn_jsonl();
    fixture.write_transcript("-tmp-native-projection", USER_UUID, &transcript);
    let source = fixture.source();
    let candidate = first_candidate(&source);

    let projection = source
        .read_projection(candidate.reference())
        .expect("bounded native projection read");
    assert_eq!(projection.bytes_read(), transcript.len() as u64);
    let NativeReadOutcome::Document(document) = projection.into_outcome() else {
        panic!("normal transcript must not be filtered");
    };
    assert_eq!(document.turns().len(), 1);
    assert_eq!(document.turns()[0].items().len(), 5);
    assert!(
        document.turns()[0]
            .items()
            .iter()
            .all(|item| item.turn_key() == document.turns()[0].key())
    );
}

#[test]
fn native_projection_canonicalization_preserves_opaque_keys_and_redacts_debug() {
    let transcript = full_turn_jsonl();
    let document = parse_document(&transcript);
    let expected_turn_key =
        crate::agent::NativeTurnKey::from_verified_bytes(*document.turns()[0].key().as_bytes())
            .expect("nonzero native turn key");
    let expected_item_keys: Vec<_> = document.turns()[0]
        .items()
        .iter()
        .map(|item| {
            crate::agent::NativeItemKey::from_verified_bytes(*item.key().as_bytes())
                .expect("nonzero native item key")
        })
        .collect();

    let read = super::canonicalize_native_projection(document, transcript.len() as u64)
        .expect("canonical key-bearing native projection");
    assert_eq!(read.agent_kind(), agentdeck_protocol::AgentKind::ClaudeCode);
    assert_eq!(read.source_bytes(), transcript.len() as u64);
    assert_eq!(read.items().len(), expected_item_keys.len());
    assert!(
        read.items()
            .iter()
            .all(|item| item.turn_key() == expected_turn_key)
    );
    assert_eq!(
        read.items()
            .iter()
            .map(|item| item.item_key())
            .collect::<Vec<_>>(),
        expected_item_keys
    );
    let debug = format!("{read:?}");
    for sentinel in ["hello", "reason", "answer", USER_UUID, TOOL_ID] {
        assert!(
            !debug.contains(sentinel),
            "Debug leaked {sentinel}: {debug}"
        );
    }
}

#[test]
fn native_projection_rejects_legacy_session_reference_without_echoing_it() {
    let private_session = "legacy-private-session-sentinel";
    let error = super::require_native_projection_reference(
        super::super::state::ResolvedClaudeCodeReference::LegacySessionId(
            agentdeck_protocol::ThreadId(private_session.to_owned()),
        ),
    )
    .expect_err("native projection cannot fall back to a legacy session id");
    assert_eq!(error.code, "adapter-native-history-reference-invalid");
    assert!(!error.message.contains(private_session));
    assert!(!format!("{error:?}").contains(private_session));
}

#[cfg(unix)]
#[test]
fn native_projection_read_rejects_static_symlink_transcript_without_following_it() {
    use std::os::unix::fs::symlink;

    let fixture = NativeFixture::new();
    let project = fixture.project("-tmp-native-projection-link");
    let outside = NativeFixture::empty_dir("native-projection-link-target");
    let target = outside.join(format!("{USER_UUID}.jsonl"));
    std::fs::write(&target, one_user_line(USER_UUID)).unwrap();
    symlink(&target, project.join(format!("{USER_UUID}.jsonl"))).unwrap();
    let reference = NativeTranscriptRefV1::from_components_for_test(
        "-tmp-native-projection-link".into(),
        format!("{USER_UUID}.jsonl").into(),
    )
    .unwrap();

    assert_code(
        fixture.source().read_projection(&reference).unwrap_err(),
        "cc-history-native-source-unsafe",
    );
}

#[cfg(unix)]
#[test]
fn native_source_rejects_symlink_at_each_verified_layer() {
    use std::os::unix::fs::symlink;

    let outside = NativeFixture::empty_dir("native-symlink-target");

    let home_link = NativeFixture::empty_dir("native-home-link-parent").join("home-link");
    symlink(&outside, &home_link).unwrap();
    assert_code(
        NativeHistorySource::from_home_for_test(&home_link, effective_uid()).unwrap_err(),
        "cc-history-native-source-unsafe",
    );

    let claude_fixture = NativeFixture::new_without_claude();
    symlink(&outside, claude_fixture.home.join(".claude")).unwrap();
    assert_code(
        NativeHistorySource::from_home_for_test(&claude_fixture.home, effective_uid()).unwrap_err(),
        "cc-history-native-source-unsafe",
    );

    let projects_fixture = NativeFixture::new_without_projects();
    symlink(&outside, projects_fixture.home.join(".claude/projects")).unwrap();
    assert_code(
        NativeHistorySource::from_home_for_test(&projects_fixture.home, effective_uid())
            .unwrap_err(),
        "cc-history-native-source-unsafe",
    );

    let project_fixture = NativeFixture::new();
    symlink(&outside, project_fixture.projects.join("-tmp-project-link")).unwrap();
    assert_code(
        next_scan_error(&project_fixture.source()),
        "cc-history-native-source-unsafe",
    );

    let transcript_fixture = NativeFixture::new();
    let project = transcript_fixture.project("-tmp-transcript-link");
    let target = outside.join("target.jsonl");
    std::fs::write(&target, one_user_line(USER_UUID)).unwrap();
    symlink(&target, project.join(format!("{USER_UUID}.jsonl"))).unwrap();
    assert_code(
        next_scan_error(&transcript_fixture.source()),
        "cc-history-native-source-unsafe",
    );
}

#[cfg(unix)]
#[test]
fn native_source_rejects_uid_mismatch_from_opened_fd() {
    let fixture = NativeFixture::new();
    let wrong_uid = effective_uid().wrapping_add(1);
    assert_code(
        NativeHistorySource::from_home_for_test(&fixture.home, wrong_uid).unwrap_err(),
        "cc-history-native-source-unsafe",
    );
}

#[cfg(unix)]
#[test]
fn native_source_rejects_fifo_jsonl_without_blocking() {
    use std::os::unix::ffi::OsStrExt;

    let fixture = NativeFixture::new();
    let fifo = fixture
        .project("-tmp-native-fifo")
        .join(format!("{USER_UUID}.jsonl"));
    let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: fifo_name is a live NUL-terminated path and mode is valid.
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);

    assert_code(
        next_scan_error(&fixture.source()),
        "cc-history-native-source-unsafe",
    );
}

#[test]
fn native_scanner_yields_before_zero_candidate_budget_and_expired_deadline() {
    let fixture = NativeFixture::new();
    fixture.write_transcript("-tmp-native-budget", USER_UUID, &one_user_line(USER_UUID));
    let source = fixture.source();
    let mut scanner = source.scanner(test_generation(1)).unwrap();

    let mut zero = NativeIoBudget::new(0, 1024, Instant::now() + Duration::from_secs(1));
    assert!(matches!(
        scanner.next(&mut zero).unwrap(),
        NativeScanStep::Yielded(NativeScanStop::CandidateLimit)
    ));

    let mut expired = NativeIoBudget::new(1, 1024, Instant::now() - Duration::from_secs(1));
    assert!(matches!(
        scanner.next(&mut expired).unwrap(),
        NativeScanStep::Yielded(NativeScanStop::Deadline)
    ));
}

#[test]
fn native_scanner_resumes_without_collecting_all_candidates() {
    let fixture = NativeFixture::new();
    for (project, id) in [
        ("-tmp-native-stream-a", USER_UUID),
        ("-tmp-native-stream-b", THINK_UUID),
        ("-tmp-native-stream-c", TEXT_UUID),
    ] {
        fixture.write_transcript(project, id, &one_user_line(id));
    }
    let source = fixture.source();
    let generation = test_generation(2);
    let mut scanner = source.scanner(generation).unwrap();
    let mut references = HashSet::new();
    loop {
        let mut budget =
            NativeIoBudget::new(1, 1024 * 1024, Instant::now() + Duration::from_secs(1));
        match scanner.next(&mut budget).unwrap() {
            NativeScanStep::Candidate(candidate) => {
                references.insert(candidate.reference().encoded_bytes_for_test());
                scanner.acknowledge(candidate).unwrap();
            }
            NativeScanStep::Yielded(NativeScanStop::CandidateLimit) => continue,
            NativeScanStep::Complete => {
                let completed = scanner.into_completed_scan().unwrap();
                assert_eq!(completed.generation(), generation);
                assert_eq!(completed.acknowledged_candidates(), 3);
                break;
            }
            other => panic!("unexpected scan step: {other:?}"),
        }
    }
    assert_eq!(references.len(), 3);
}

#[test]
fn native_scanner_rejects_zero_generation() {
    let fixture = NativeFixture::new();
    assert_code(
        fixture.source().scanner([0; 16]).unwrap_err(),
        "cc-history-native-scan-generation-invalid",
    );
}

#[test]
fn native_scanner_replays_pending_candidate_without_recharging_budget() {
    let fixture = NativeFixture::new();
    fixture.write_transcript("-tmp-native-pending", USER_UUID, &one_user_line(USER_UUID));
    let generation = test_generation(3);
    let mut scanner = fixture.source().scanner(generation).unwrap();
    let mut one_candidate =
        NativeIoBudget::new(1, 1024 * 1024, Instant::now() + Duration::from_secs(1));

    let first = match scanner.next(&mut one_candidate).unwrap() {
        NativeScanStep::Candidate(candidate) => candidate,
        other => panic!("expected first candidate, got {other:?}"),
    };
    let expected_reference = first.reference().encoded_bytes_for_test();
    let retry = match scanner.next(&mut one_candidate).unwrap() {
        NativeScanStep::Candidate(candidate) => candidate,
        other => panic!("pending candidate must be replayed without budget, got {other:?}"),
    };
    assert_eq!(
        retry.reference().encoded_bytes_for_test(),
        expected_reference
    );
    scanner.acknowledge(retry).unwrap();

    assert!(matches!(
        scanner.next(&mut one_candidate).unwrap(),
        NativeScanStep::Yielded(NativeScanStop::CandidateLimit)
    ));
    let mut resume = generous_budget();
    assert!(matches!(
        scanner.next(&mut resume).unwrap(),
        NativeScanStep::Complete
    ));
    let completed = scanner.into_completed_scan().unwrap();
    assert_eq!(completed.generation(), generation);
    assert_eq!(completed.acknowledged_candidates(), 1);
    let debug = format!("{completed:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&format!("{generation:?}")));
}

#[test]
fn native_scanner_rejects_wrong_candidate_ack_and_keeps_pending() {
    let expected_fixture = NativeFixture::new();
    expected_fixture.write_transcript(
        "-tmp-native-expected-ack",
        USER_UUID,
        &one_user_line(USER_UUID),
    );
    let wrong_fixture = NativeFixture::new();
    wrong_fixture.write_transcript(
        "-tmp-native-wrong-ack",
        THINK_UUID,
        &one_user_line(THINK_UUID),
    );

    let mut scanner = expected_fixture
        .source()
        .scanner(test_generation(4))
        .unwrap();
    let expected = match scanner.next(&mut generous_budget()).unwrap() {
        NativeScanStep::Candidate(candidate) => candidate,
        other => panic!("expected pending candidate, got {other:?}"),
    };
    let expected_reference = expected.reference().encoded_bytes_for_test();
    let mut wrong_scanner = wrong_fixture.source().scanner(test_generation(5)).unwrap();
    let wrong = match wrong_scanner.next(&mut generous_budget()).unwrap() {
        NativeScanStep::Candidate(candidate) => candidate,
        other => panic!("expected wrong candidate, got {other:?}"),
    };

    assert_code(
        scanner.acknowledge(wrong).unwrap_err(),
        "cc-history-native-scan-ack-invalid",
    );
    let retry = match scanner.next(&mut generous_budget()).unwrap() {
        NativeScanStep::Candidate(candidate) => candidate,
        other => panic!("wrong ACK must leave candidate pending, got {other:?}"),
    };
    assert_eq!(
        retry.reference().encoded_bytes_for_test(),
        expected_reference
    );
    scanner.acknowledge(retry).unwrap();
    assert!(matches!(
        scanner.next(&mut generous_budget()).unwrap(),
        NativeScanStep::Complete
    ));
    assert_eq!(
        scanner
            .into_completed_scan()
            .unwrap()
            .acknowledged_candidates(),
        1
    );
}

#[test]
fn native_scanner_partial_yield_unacked_and_drop_paths_have_no_completion() {
    let fixture = NativeFixture::new();
    fixture.write_transcript(
        "-tmp-native-incomplete",
        USER_UUID,
        &one_user_line(USER_UUID),
    );
    let source = fixture.source();

    let partial = source.scanner(test_generation(6)).unwrap();
    assert_code(
        partial.into_completed_scan().unwrap_err(),
        "cc-history-native-scan-incomplete",
    );

    let mut yielded = source.scanner(test_generation(7)).unwrap();
    let mut zero = NativeIoBudget::new(0, 1024, Instant::now() + Duration::from_secs(1));
    assert!(matches!(
        yielded.next(&mut zero).unwrap(),
        NativeScanStep::Yielded(NativeScanStop::CandidateLimit)
    ));
    assert_code(
        yielded.into_completed_scan().unwrap_err(),
        "cc-history-native-scan-incomplete",
    );

    let mut unacknowledged = source.scanner(test_generation(8)).unwrap();
    assert!(matches!(
        unacknowledged.next(&mut generous_budget()).unwrap(),
        NativeScanStep::Candidate(_)
    ));
    assert_code(
        unacknowledged.into_completed_scan().unwrap_err(),
        "cc-history-native-scan-incomplete",
    );

    let abandoned = source.scanner(test_generation(9)).unwrap();
    let no_witness = {
        drop(abandoned);
        None::<super::native::CompletedNativeScan>
    };
    assert!(no_witness.is_none());
}

#[cfg(unix)]
#[test]
fn native_scanner_error_poisoning_prevents_completion() {
    use std::os::unix::fs::symlink;

    let fixture = NativeFixture::new();
    let outside = NativeFixture::empty_dir("native-scan-error-target");
    symlink(&outside, fixture.projects.join("-tmp-native-error-link")).unwrap();
    let mut scanner = fixture.source().scanner(test_generation(10)).unwrap();
    assert_code(
        scanner.next(&mut generous_budget()).unwrap_err(),
        "cc-history-native-source-unsafe",
    );
    assert_code(
        scanner.next(&mut generous_budget()).unwrap_err(),
        "cc-history-native-scan-failed",
    );
    assert_code(
        scanner.into_completed_scan().unwrap_err(),
        "cc-history-native-scan-incomplete",
    );
    let _ = std::fs::remove_dir_all(outside);
}

#[test]
fn native_reader_stops_at_byte_limit_plus_one() {
    let content = format!(
        "{{\"type\":\"user\",\"uuid\":\"{USER_UUID}\",\"parentUuid\":null,\"message\":{{\"content\":\"{}\"}}}}\n",
        "x".repeat(4096)
    );
    let mut budget = NativeIoBudget::new(1, 128, Instant::now() + Duration::from_secs(1));
    let error = parse_native_jsonl(
        BufReader::new(Cursor::new(content.into_bytes())),
        &mut budget,
        NativeParseLimits::default(),
        false,
    )
    .unwrap_err();
    assert_code(error, "cc-history-native-budget-bytes");
    assert!(budget.bytes_read() <= 129);
}

#[test]
fn native_reader_rejects_small_source_with_high_decoded_dom_amplification() {
    const RETAINED_LIMIT: usize = 512 * 1024;
    const SINGLETON_OBJECTS: usize = 1_000;
    let mut content = format!(
        "{{\"type\":\"user\",\"uuid\":\"{USER_UUID}\",\"parentUuid\":null,\"message\":{{\"content\":\"hello\"}},\"ignored\":["
    );
    for index in 0..SINGLETON_OBJECTS {
        if index != 0 {
            content.push(',');
        }
        content.push_str(r#"{"a":null}"#);
    }
    content.push_str("]}\n");
    assert!(
        content.len() < RETAINED_LIMIT / 8,
        "fixture must demonstrate decoded/container amplification over raw bytes"
    );

    let permissive = NativeParseLimits {
        max_retained_bytes: 8 * 1024 * 1024,
        ..NativeParseLimits::default()
    };
    parse_native_jsonl(
        BufReader::new(Cursor::new(content.as_bytes())),
        &mut generous_budget(),
        permissive,
        false,
    )
    .expect("fixture is valid native JSONL when retained capacity is available");

    let bounded = NativeParseLimits {
        max_retained_bytes: RETAINED_LIMIT,
        ..NativeParseLimits::default()
    };
    let error = parse_native_jsonl(
        BufReader::new(Cursor::new(content.as_bytes())),
        &mut generous_budget(),
        bounded,
        false,
    )
    .expect_err("content-aware decoded retained gate must reject before Value allocation");
    assert_code(error, "cc-history-native-too-large");
}

#[test]
fn native_reader_does_not_treat_retained_cap_truncation_as_incomplete_eof_tail() {
    let content = format!(
        "{{\"type\":\"user\",\"uuid\":\"{USER_UUID}\",\"parentUuid\":null,\"message\":{{\"content\":\"{}\"}}}}\n",
        "x".repeat(24 * 1024)
    );
    let limits = NativeParseLimits {
        max_retained_bytes: 80 * 1024,
        ..NativeParseLimits::default()
    };
    let error = parse_native_jsonl(
        BufReader::new(Cursor::new(content.as_bytes())),
        &mut generous_budget(),
        limits,
        false,
    )
    .expect_err("retained raw cap must fail closed while unread line bytes remain");
    assert_code(error, "cc-history-native-too-large");
}

#[cfg(unix)]
#[test]
fn native_private_ref_v1_roundtrips_raw_components_and_redacts_debug() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let reference = NativeTranscriptRefV1::from_components_for_test(
        std::ffi::OsString::from_vec(b"project-\xff".to_vec()),
        std::ffi::OsString::from_vec(b"10000000-0000-4000-8000-000000000001.jsonl".to_vec()),
    )
    .unwrap();
    let encoded = reference.encoded_bytes_for_test();
    let decoded = NativeTranscriptRefV1::decode(&encoded).unwrap();
    assert_eq!(decoded.project_component().as_bytes(), b"project-\xff");
    assert_eq!(
        decoded.transcript_filename().as_bytes(),
        b"10000000-0000-4000-8000-000000000001.jsonl"
    );
    assert_eq!(format!("{decoded:?}"), "NativeTranscriptRefV1([REDACTED])");
}

#[test]
fn native_private_ref_v1_binds_project_and_filename_and_rejects_bad_encodings() {
    let first = NativeTranscriptRefV1::from_components_for_test(
        "-tmp-project-a".into(),
        format!("{USER_UUID}.jsonl").into(),
    )
    .unwrap();
    let second = NativeTranscriptRefV1::from_components_for_test(
        "-tmp-project-b".into(),
        format!("{USER_UUID}.jsonl").into(),
    )
    .unwrap();
    assert_ne!(
        first.encoded_bytes_for_test(),
        second.encoded_bytes_for_test()
    );

    let mut unknown = first.encoded_bytes_for_test();
    unknown[8] = 9;
    assert_code(
        NativeTranscriptRefV1::decode(&unknown).unwrap_err(),
        "cc-history-native-ref-version",
    );
    let mut trailing = first.encoded_bytes_for_test();
    trailing.push(0);
    assert_code(
        NativeTranscriptRefV1::decode(&trailing).unwrap_err(),
        "cc-history-native-ref-invalid",
    );
    for (project, filename) in [
        ("..", "10000000-0000-4000-8000-000000000001.jsonl"),
        ("a/b", "10000000-0000-4000-8000-000000000001.jsonl"),
        ("safe", "not-a-transcript.txt"),
    ] {
        assert!(
            NativeTranscriptRefV1::from_components_for_test(project.into(), filename.into())
                .is_err()
        );
    }
}

#[test]
fn native_parser_returns_stable_turn_and_item_keys_for_uuid_parent_chain() {
    let document = parse_document(&full_turn_jsonl());
    assert_eq!(document.turns().len(), 1);
    let turn = &document.turns()[0];
    assert_eq!(turn.items().len(), 5);
    let keys: HashSet<_> = turn
        .items()
        .iter()
        .map(|item| item.key().as_bytes_for_test())
        .collect();
    assert_eq!(keys.len(), 5);
    assert!(
        turn.items()
            .iter()
            .all(|item| item.turn_key() == turn.key())
    );
}

#[test]
fn native_parser_append_preserves_existing_keys() {
    let before = parse_document(&full_turn_jsonl());
    let appended = format!(
        "{}{{\"type\":\"assistant\",\"uuid\":\"{SECOND_UUID}\",\"parentUuid\":\"{RESULT_UUID}\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":\"later\"}}]}}}}\n",
        full_turn_jsonl()
    );
    let after = parse_document(&appended);
    let before_keys: Vec<_> = before.turns()[0]
        .items()
        .iter()
        .map(|item| item.key().as_bytes_for_test())
        .collect();
    let after_keys: Vec<_> = after.turns()[0]
        .items()
        .iter()
        .take(before_keys.len())
        .map(|item| item.key().as_bytes_for_test())
        .collect();
    assert_eq!(after_keys, before_keys);
}

#[test]
fn native_item_keys_do_not_depend_on_content_array_order() {
    let prefix = one_user_line(USER_UUID);
    let first = format!(
        "{prefix}{{\"type\":\"assistant\",\"uuid\":\"{TEXT_UUID}\",\"parentUuid\":\"{USER_UUID}\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":\"answer\"}},{{\"type\":\"thinking\",\"thinking\":\"reason\"}},{{\"type\":\"tool_use\",\"id\":\"{TOOL_ID}\",\"name\":\"Bash\",\"input\":{{\"command\":\"echo hi\"}}}}]}}}}\n"
    );
    let second = format!(
        "{prefix}{{\"type\":\"assistant\",\"uuid\":\"{TEXT_UUID}\",\"parentUuid\":\"{USER_UUID}\",\"message\":{{\"content\":[{{\"type\":\"tool_use\",\"id\":\"{TOOL_ID}\",\"name\":\"Bash\",\"input\":{{\"command\":\"echo hi\"}}}},{{\"type\":\"thinking\",\"thinking\":\"reason\"}},{{\"type\":\"text\",\"text\":\"answer\"}}]}}}}\n"
    );
    let keys = |document: super::native::NativeHistoryDocument| {
        document.turns()[0]
            .items()
            .iter()
            .map(|item| item.key().as_bytes_for_test())
            .collect::<HashSet<_>>()
    };
    assert_eq!(keys(parse_document(&first)), keys(parse_document(&second)));
}

#[test]
fn native_parser_keys_ignore_title_cwd_and_session_id() {
    let a = format!(
        "{{\"type\":\"user\",\"uuid\":\"{USER_UUID}\",\"parentUuid\":null,\"cwd\":\"/a\",\"sessionId\":\"first\",\"message\":{{\"content\":\"hello\"}}}}\n{{\"type\":\"custom-title\",\"customTitle\":\"A\"}}\n"
    );
    let b = format!(
        "{{\"type\":\"user\",\"uuid\":\"{USER_UUID}\",\"parentUuid\":null,\"cwd\":\"/b\",\"sessionId\":\"second\",\"message\":{{\"content\":\"hello\"}}}}\n{{\"type\":\"custom-title\",\"customTitle\":\"B\"}}\n"
    );
    let a = parse_document(&a);
    let b = parse_document(&b);
    assert_eq!(a.turns()[0].key(), b.turns()[0].key());
    assert_eq!(a.turns()[0].items()[0].key(), b.turns()[0].items()[0].key());
}

#[test]
fn native_parser_rejects_duplicate_record_item_and_tool_keys() {
    let duplicate_record = format!("{}{}", one_user_line(USER_UUID), one_user_line(USER_UUID));
    assert_parse_code(&duplicate_record, "cc-history-native-duplicate-key");

    let duplicate_item = format!(
        "{}{{\"type\":\"assistant\",\"uuid\":\"{TEXT_UUID}\",\"parentUuid\":\"{USER_UUID}\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":\"a\"}},{{\"type\":\"text\",\"text\":\"b\"}}]}}}}\n",
        one_user_line(USER_UUID)
    );
    assert_parse_code(&duplicate_item, "cc-history-native-duplicate-key");

    let duplicate_tool = format!(
        "{}{{\"type\":\"assistant\",\"uuid\":\"{TOOL_UUID}\",\"parentUuid\":\"{USER_UUID}\",\"message\":{{\"content\":[{{\"type\":\"tool_use\",\"id\":\"{TOOL_ID}\",\"name\":\"Bash\",\"input\":{{\"command\":\"one\"}}}}]}}}}\n{{\"type\":\"assistant\",\"uuid\":\"{SECOND_UUID}\",\"parentUuid\":\"{TOOL_UUID}\",\"message\":{{\"content\":[{{\"type\":\"tool_use\",\"id\":\"{TOOL_ID}\",\"name\":\"Bash\",\"input\":{{\"command\":\"two\"}}}}]}}}}\n",
        one_user_line(USER_UUID)
    );
    assert_parse_code(&duplicate_tool, "cc-history-native-duplicate-key");
}

#[test]
fn native_parser_rejects_orphan_tool_result_instead_of_emitting_raw() {
    let orphan = format!(
        "{}{{\"type\":\"user\",\"uuid\":\"{RESULT_UUID}\",\"parentUuid\":\"{USER_UUID}\",\"message\":{{\"content\":[{{\"type\":\"tool_result\",\"tool_use_id\":\"missing-tool\",\"content\":\"raw sentinel\"}}]}}}}\n",
        one_user_line(USER_UUID)
    );
    assert_parse_code(&orphan, "cc-history-native-key-invalid");
}

#[test]
fn native_parser_rejects_malformed_middle_and_noncanonical_item_uuid() {
    let malformed = format!(
        "{}not-json\n{}",
        one_user_line(USER_UUID),
        one_user_line(SECOND_UUID)
    );
    assert_parse_code(&malformed, "cc-history-native-malformed");

    let missing = r#"{"type":"user","parentUuid":null,"message":{"content":"hello"}}
"#;
    assert_parse_code(missing, "cc-history-native-key-invalid");
    let uppercase = one_user_line(&"abcdefab-cdef-4abc-8def-abcdefabcdef".to_ascii_uppercase());
    assert_parse_code(&uppercase, "cc-history-native-key-invalid");

    let missing_parent = format!(
        "{{\"type\":\"assistant\",\"uuid\":\"{TEXT_UUID}\",\"parentUuid\":\"{USER_UUID}\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":\"orphan\"}}]}}}}\n"
    );
    assert_parse_code(&missing_parent, "cc-history-native-key-invalid");
}

#[test]
fn native_parser_accepts_complete_no_newline_and_only_eof_incomplete_tail() {
    let complete = one_user_line(USER_UUID);
    let complete = complete.trim_end_matches('\n');
    let document = parse_document(complete);
    assert_eq!(document.tail(), NativeTailState::Complete);

    let incomplete = format!(
        "{}{{\"type\":\"assistant\",\"uuid\":\"{TEXT_UUID}\",\"parentUuid\":\"{USER_UUID}\",\"message\":",
        one_user_line(USER_UUID)
    );
    let document = parse_document(&incomplete);
    assert_eq!(document.tail(), NativeTailState::IncompleteIgnored);
    assert_eq!(document.turns()[0].items().len(), 1);

    let malformed_with_newline = format!("{}{{bad}}\n", one_user_line(USER_UUID));
    assert_parse_code(&malformed_with_newline, "cc-history-native-malformed");
}

#[test]
fn native_parser_filters_memory_agent_prompt() {
    let content = format!(
        "{{\"type\":\"user\",\"uuid\":\"{USER_UUID}\",\"parentUuid\":null,\"message\":{{\"content\":\"Hello memory agent, continue observing\"}}}}\n"
    );
    let outcome = parse_outcome(&content, false).unwrap();
    assert!(matches!(outcome, NativeReadOutcome::FilteredObserver));
}

#[test]
fn native_debug_and_error_surfaces_hide_path_uuid_tool_id_and_raw_payload() {
    let fixture = NativeFixture::new();
    fixture.write_transcript(
        "-tmp-private-project-sentinel",
        USER_UUID,
        &full_turn_jsonl(),
    );
    let source = fixture.source();
    let candidate = first_candidate(&source);
    let candidate_debug = format!("{candidate:?}");
    let reference_debug = format!("{:?}", candidate.reference());
    let document = parse_document(&full_turn_jsonl());
    let turn_debug = format!("{:?}", document.turns()[0].key());
    let item_debug = format!("{:?}", document.turns()[0].items()[3].key());

    for surface in [
        candidate_debug.as_str(),
        reference_debug.as_str(),
        turn_debug.as_str(),
        item_debug.as_str(),
    ] {
        for sentinel in [
            "private-project-sentinel",
            USER_UUID,
            TOOL_UUID,
            TOOL_ID,
            ".jsonl",
        ] {
            assert!(
                !surface.contains(sentinel),
                "Debug leaked {sentinel}: {surface}"
            );
        }
    }

    let orphan = format!(
        "{}{{\"type\":\"user\",\"uuid\":\"{RESULT_UUID}\",\"parentUuid\":\"{USER_UUID}\",\"message\":{{\"content\":[{{\"type\":\"tool_result\",\"tool_use_id\":\"missing-tool\",\"content\":\"raw-payload-sentinel\"}}]}}}}\n",
        one_user_line(USER_UUID)
    );
    let error_debug = format!("{:?}", parse_outcome(&orphan, false).unwrap_err());
    assert!(!error_debug.contains("raw-payload-sentinel"));
    assert!(!error_debug.contains("missing-tool"));
}

fn parse_document(content: &str) -> super::native::NativeHistoryDocument {
    let outcome = parse_outcome(content, false).expect("parse native document");
    let NativeReadOutcome::Document(document) = outcome else {
        panic!("fixture unexpectedly filtered");
    };
    document
}

fn parse_outcome(
    content: &str,
    observer_project: bool,
) -> Result<NativeReadOutcome, NativeHistoryError> {
    parse_native_jsonl(
        BufReader::new(Cursor::new(content.as_bytes())),
        &mut generous_budget(),
        NativeParseLimits::default(),
        observer_project,
    )
}

fn assert_parse_code(content: &str, expected: &str) {
    assert_code(parse_outcome(content, false).unwrap_err(), expected);
}

fn full_turn_jsonl() -> String {
    format!(
        "{}{{\"type\":\"assistant\",\"uuid\":\"{THINK_UUID}\",\"parentUuid\":\"{USER_UUID}\",\"message\":{{\"content\":[{{\"type\":\"thinking\",\"thinking\":\"reason\"}}]}}}}\n{{\"type\":\"assistant\",\"uuid\":\"{TEXT_UUID}\",\"parentUuid\":\"{THINK_UUID}\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":\"answer\"}}]}}}}\n{{\"type\":\"assistant\",\"uuid\":\"{TOOL_UUID}\",\"parentUuid\":\"{TEXT_UUID}\",\"message\":{{\"content\":[{{\"type\":\"tool_use\",\"id\":\"{TOOL_ID}\",\"name\":\"Bash\",\"input\":{{\"command\":\"echo hi\"}}}}]}}}}\n{{\"type\":\"user\",\"uuid\":\"{RESULT_UUID}\",\"parentUuid\":\"{TOOL_UUID}\",\"message\":{{\"content\":[{{\"type\":\"tool_result\",\"tool_use_id\":\"{TOOL_ID}\",\"content\":\"hi\",\"is_error\":false}}]}}}}\n",
        one_user_line(USER_UUID)
    )
}

fn one_user_line(uuid: &str) -> String {
    format!(
        "{{\"type\":\"user\",\"uuid\":\"{uuid}\",\"parentUuid\":null,\"cwd\":\"/tmp/native\",\"message\":{{\"content\":\"hello\"}}}}\n"
    )
}

fn generous_budget() -> NativeIoBudget {
    NativeIoBudget::new(
        2_000,
        64 * 1024 * 1024,
        Instant::now() + Duration::from_secs(2),
    )
}

fn first_candidate(source: &NativeHistorySource) -> super::native::NativeHistoryCandidate {
    let mut scanner = source.scanner(test_generation(250)).unwrap();
    match scanner.next(&mut generous_budget()).unwrap() {
        NativeScanStep::Candidate(candidate) => candidate,
        other => panic!("expected candidate, got {other:?}"),
    }
}

fn next_scan_error(source: &NativeHistorySource) -> NativeHistoryError {
    let mut scanner = source.scanner(test_generation(251)).unwrap();
    scanner.next(&mut generous_budget()).unwrap_err()
}

fn test_generation(byte: u8) -> [u8; 16] {
    assert_ne!(byte, 0);
    [byte; 16]
}

fn assert_code(error: NativeHistoryError, expected: &str) {
    assert_eq!(error.code(), expected, "unexpected error: {error:?}");
}

#[cfg(unix)]
fn effective_uid() -> libc::uid_t {
    // SAFETY: geteuid has no preconditions and only reads process credentials.
    unsafe { libc::geteuid() }
}

struct NativeFixture {
    home: PathBuf,
    projects: PathBuf,
}

impl NativeFixture {
    fn new() -> Self {
        let fixture = Self::new_without_claude();
        std::fs::create_dir_all(&fixture.projects).unwrap();
        fixture
    }

    fn new_without_claude() -> Self {
        let home = Self::empty_dir("native-home");
        let projects = home.join(".claude/projects");
        Self { home, projects }
    }

    fn new_without_projects() -> Self {
        let fixture = Self::new_without_claude();
        std::fs::create_dir_all(fixture.home.join(".claude")).unwrap();
        fixture
    }

    fn empty_dir(label: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agentdeck-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn project(&self, name: &str) -> PathBuf {
        let path = self.projects.join(name);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_transcript(&self, project: &str, id: &str, content: &str) -> PathBuf {
        let path = self.project(project).join(format!("{id}.jsonl"));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[cfg(unix)]
    fn source(&self) -> NativeHistorySource {
        NativeHistorySource::from_home_for_test(&self.home, effective_uid()).unwrap()
    }

    #[cfg(not(unix))]
    fn source(&self) -> NativeHistorySource {
        NativeHistorySource::from_home_for_test(&self.home, 0).unwrap()
    }
}

impl Drop for NativeFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}
