use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeckd::config::compiled_stable_keychain_access_group;

const MAIN_SOURCE: &str = include_str!("../src/main.rs");

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        // macOS sockaddr_un 只有 104 bytes；测试 root 必须像生产 ephemeral
        // namespace 一样保持很短，不能让夹具路径先耗尽预算。
        let root = PathBuf::from("/tmp").join(format!(
            "ads-{label}-{}-{:x}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("make test root private");
        }
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn daemon(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentdeckd"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run agentdeckd")
}

fn assert_rejected(args: &[&str], code: &str) {
    let output = daemon(args);
    assert_eq!(
        output.status.code(),
        Some(2),
        "args {args:?}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(code),
        "args {args:?} did not expose {code}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_source_order(label: &str, source: &str, needles: &[&str]) {
    let mut cursor = 0;
    for needle in needles {
        let offset = source[cursor..]
            .find(needle)
            .unwrap_or_else(|| panic!("{label}: missing {needle:?}"));
        cursor += offset + needle.len();
    }
}

#[test]
fn runtime_bootstrap_quiesces_owned_resources_before_releasing_singleton() {
    // 威胁场景：Store 已打开后 Core 构造或 recovery 失败，启动路径提前返回；
    // SQLite worker/lock 未收到 shutdown 回执，singleton 却已释放，下一实例会撞上残留资源。
    let loop_start = MAIN_SOURCE
        .find("fn run_main_loop(")
        .expect("run_main_loop source");
    let loop_end = MAIN_SOURCE[loop_start..]
        .find("\nfn main()")
        .map(|offset| loop_start + offset)
        .expect("main source");
    let loop_source = &MAIN_SOURCE[loop_start..loop_end];

    assert_source_order(
        "store construction failure cleanup",
        loop_source,
        &[
            "RuntimeStoreHandle::open",
            "RuntimeCore::new_production(store.clone(), router.clone())",
            "store.shutdown().await",
            "return Err(MainLoopFailure::runtime(error))",
        ],
    );
    assert_source_order(
        "core-owned cleanup",
        loop_source,
        &[
            "let run_result = async",
            ".recover_for_startup()",
            "hub.run(",
            "let shutdown = core.shutdown().await",
            "run_result?",
            "shutdown.map_err(MainLoopFailure::runtime)",
        ],
    );

    let main_source = &MAIN_SOURCE[loop_end..];
    assert_source_order(
        "singleton lifetime",
        main_source,
        &[
            "match run_main_loop(&config, storage_kek)",
            "drop((key_store, singleton_guard))",
        ],
    );
}

#[test]
fn rejects_incomplete_or_mismatched_startup_modes_with_typed_codes() {
    assert_rejected(
        &["--ephemeral", "--profile", "dev", "--selfcheck"],
        "daemon.config.ephemeral_requires_no_remote",
    );
    assert_rejected(
        &["--no-remote", "--profile", "dev", "--selfcheck"],
        "daemon.config.no_remote_requires_ephemeral",
    );
    assert_rejected(
        &["--profile", "dev", "--selfcheck"],
        "daemon.config.dev_requires_ephemeral",
    );
    assert_rejected(
        &[
            "--ephemeral",
            "--no-remote",
            "--profile",
            "stable",
            "--selfcheck",
        ],
        "daemon.config.stable_forbids_ephemeral",
    );
    assert_rejected(
        &["--profile", "preview", "--selfcheck"],
        "daemon.cli.invalid_profile",
    );
}

#[test]
fn data_dir_override_is_diagnostics_only() {
    assert_rejected(
        &[
            "--ephemeral",
            "--no-remote",
            "--profile",
            "dev",
            "--selfcheck",
            "--data-dir",
            "/tmp/forbidden-selfcheck",
        ],
        "daemon.cli.data_dir_forbidden",
    );
    assert_rejected(
        &["--data-dir", "/tmp/forbidden-serve"],
        "daemon.cli.data_dir_forbidden",
    );
}

#[test]
fn unsigned_stable_daemon_cannot_be_provisioned_by_runtime_environment() {
    if compiled_stable_keychain_access_group().is_some() {
        // Release-signed builds exercise the real Keychain path in the gated signing test.
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_agentdeckd"))
        .arg("--selfcheck")
        .env(
            "AGENTDECK_DAEMON_KEYCHAIN_ACCESS_GROUP",
            "RUNTIMEENV.com.agentdeck.agentdeckd.stable",
        )
        .stdin(Stdio::null())
        .output()
        .expect("run unsigned stable daemon");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("daemon.keystore.access_group_unconfigured"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn ephemeral_selfcheck_uses_a_fresh_private_namespace_each_time() {
    let root = TestRoot::new("ephemeral");
    let first = run_ephemeral_selfcheck(root.path());
    let second = run_ephemeral_selfcheck(root.path());

    assert_ne!(first, second);
    for data_dir in [first, second] {
        assert!(data_dir.starts_with(root.path()), "{}", data_dir.display());
        assert!(data_dir.join("agentdeckd.lock").is_file());
        assert!(data_dir.join("diagnostic.log").is_file());
        let runs = data_dir.join("runs");
        assert!(runs.is_dir());
        assert!(
            fs::read_dir(runs)
                .expect("read selfcheck records")
                .any(|entry| entry
                    .expect("record entry")
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "jsonl"))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&data_dir)
                    .expect("ephemeral namespace metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }
}

fn run_ephemeral_selfcheck(temp_root: &Path) -> PathBuf {
    let output = Command::new(env!("CARGO_BIN_EXE_agentdeckd"))
        .args([
            "--ephemeral",
            "--no-remote",
            "--profile",
            "dev",
            "--selfcheck",
        ])
        .env("TMPDIR", temp_root)
        .env(
            "AGENTDECK_DATA_DIR",
            temp_root.join("legacy-override-must-not-win"),
        )
        .stdin(Stdio::null())
        .output()
        .expect("run ephemeral selfcheck");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 selfcheck output");
    assert_eq!(stdout.lines().next(), Some("OK"));
    let summary: serde_json::Value =
        serde_json::from_str(stdout.lines().nth(1).expect("selfcheck JSON summary line"))
            .expect("parse selfcheck JSON");
    PathBuf::from(
        summary["dataDir"]
            .as_str()
            .expect("selfcheck dataDir string"),
    )
}
