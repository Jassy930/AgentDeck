use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[cfg(feature = "tls")]
use agentdeck_relay::config::RelayV2TlsPaths;
use agentdeck_relay::config::{
    RelayV2ConfigError, RelayV2ServerConfig, RelayV2StoreSettings, RelayV2TransportMode,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn env(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn load(
    args: &[&str],
    environment: &BTreeMap<String, String>,
    cwd: &Path,
) -> Result<RelayV2ServerConfig, RelayV2ConfigError> {
    RelayV2ServerConfig::load_from(args.iter().copied(), environment, cwd)
}

fn insecure_args() -> Vec<&'static str> {
    vec!["agentdeck-relay", "--allow-insecure-loopback"]
}

#[test]
fn dev_defaults_are_absolute_and_still_require_explicit_loopback_opt_in() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = load(&insecure_args(), &BTreeMap::new(), temp.path()).expect("load defaults");

    assert_eq!(config.bind, "127.0.0.1:8443".parse::<SocketAddr>().unwrap());
    assert_eq!(
        config.health_bind,
        "127.0.0.1:8444".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        config.store.storage_path,
        temp.path().join("agentdeck-relay-data/relay-v2.db")
    );
    assert!(config.store.storage_path.is_absolute());
    assert_eq!(config.log_level, "info");
    assert_eq!(config.transport, RelayV2TransportMode::InsecureLoopback);

    let error = load(&["agentdeck-relay"], &BTreeMap::new(), temp.path())
        .expect_err("loopback plaintext must require an explicit opt-in");
    assert!(matches!(
        error,
        RelayV2ConfigError::InsecureLoopbackOptInRequired
    ));
    assert_eq!(
        error.code(),
        "relay.transport.insecure_loopback_opt_in_required"
    );
}

#[test]
fn loader_merges_cli_over_env_over_toml_over_defaults_per_field() {
    let temp = tempfile::tempdir().expect("tempdir");
    let file_storage = temp.path().join("file.db");
    let env_storage = temp.path().join("env.db");
    let cli_storage = temp.path().join("cli.db");
    let config_path = temp.path().join("relay.toml");
    std::fs::write(
        &config_path,
        format!(
            "bind = \"127.0.0.1:7001\"\nhealth_bind = \"127.0.0.1:7002\"\nstorage = {:?}\nallow_insecure_loopback = true\nlog_level = \"warn\"\n",
            file_storage
        ),
    )
    .expect("write config");

    let environment = env(&[
        ("AGENTDECK_RELAY_BIND", "127.0.0.1:7101"),
        ("AGENTDECK_RELAY_STORAGE", env_storage.to_str().unwrap()),
        ("AGENTDECK_RELAY_LOG", "debug"),
    ]);
    let args = [
        "agentdeck-relay",
        "--config",
        config_path.to_str().unwrap(),
        "--bind",
        "127.0.0.1:7201",
        "--storage",
        cli_storage.to_str().unwrap(),
        "--allow-insecure-loopback",
    ];

    let config = load(&args, &environment, temp.path()).expect("load layered config");

    assert_eq!(config.bind, "127.0.0.1:7201".parse().unwrap());
    assert_eq!(config.health_bind, "127.0.0.1:7002".parse().unwrap());
    assert_eq!(config.store.storage_path, cli_storage);
    assert_eq!(config.log_level, "debug");
    assert_eq!(config.transport, RelayV2TransportMode::InsecureLoopback);
}

#[test]
fn store_limits_are_all_configurable_with_the_same_layer_priority() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = temp.path().join("limits.toml");
    std::fs::write(
        &config_path,
        format!(
            "storage = {:?}\nallow_insecure_loopback = true\nmax_frames_per_stream = 101\nmax_bytes_per_stream = 1048576\nmax_age_ms = 60000\nmax_bytes_per_machine = 2097152\nmax_bytes_global = 4194304\nreplay_page_max_frames = 7\nreplay_page_max_bytes = 4194304\ndisk_reserve_bytes = 65536\ndisk_reserve_percent = 3\nmax_enrollment_codes = 99\n",
            temp.path().join("relay.db")
        ),
    )
    .expect("write limit config");
    let environment = env(&[
        ("AGENTDECK_RELAY_MAX_BYTES_GLOBAL", "8388608"),
        ("AGENTDECK_RELAY_DISK_RESERVE_PERCENT", "4"),
    ]);
    let config = load(
        &[
            "agentdeck-relay",
            "--config",
            config_path.to_str().unwrap(),
            "--max-frames-per-stream",
            "202",
        ],
        &environment,
        temp.path(),
    )
    .expect("load every Store limit");

    assert_eq!(config.store.max_frames_per_stream, 202);
    assert_eq!(config.store.max_bytes_per_stream, 1_048_576);
    assert_eq!(config.store.max_age_ms, 60_000);
    assert_eq!(config.store.max_bytes_per_machine, 2_097_152);
    assert_eq!(config.store.max_bytes_global, 8_388_608);
    assert_eq!(config.store.replay_page_max_frames, 7);
    assert_eq!(config.store.replay_page_max_bytes, 4_194_304);
    assert_eq!(config.store.disk_reserve_bytes, 65_536);
    assert_eq!(config.store.disk_reserve_percent, 4);
    assert_eq!(config.store.max_enrollment_codes, 99);

    let invalid = load(
        &insecure_args(),
        &env(&[("AGENTDECK_RELAY_DISK_RESERVE_PERCENT", "not-a-number")]),
        temp.path(),
    )
    .expect_err("invalid numeric env must not silently use a default");
    assert!(matches!(
        invalid,
        RelayV2ConfigError::InvalidEnvironment {
            key: "AGENTDECK_RELAY_DISK_RESERVE_PERCENT"
        }
    ));
}

#[test]
fn cli_config_path_wins_over_env_config_path_and_relative_config_is_cwd_relative() {
    let temp = tempfile::tempdir().expect("tempdir");
    let env_config = temp.path().join("env.toml");
    let cli_config = temp.path().join("cli.toml");
    std::fs::write(
        &env_config,
        format!(
            "storage = {:?}\nallow_insecure_loopback = true\nlog_level = \"error\"\n",
            temp.path().join("env.db")
        ),
    )
    .expect("write env config");
    std::fs::write(
        &cli_config,
        format!(
            "storage = {:?}\nallow_insecure_loopback = true\nlog_level = \"trace\"\n",
            temp.path().join("cli.db")
        ),
    )
    .expect("write cli config");

    let config = load(
        &["agentdeck-relay", "--config", "cli.toml"],
        &env(&[("AGENTDECK_RELAY_CONFIG", env_config.to_str().unwrap())]),
        temp.path(),
    )
    .expect("load selected config");

    assert_eq!(config.log_level, "trace");
    assert_eq!(config.store.storage_path, temp.path().join("cli.db"));
}

#[test]
fn relative_storage_and_non_loopback_health_are_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let relative = load(
        &[
            "agentdeck-relay",
            "--storage",
            "relative/relay.db",
            "--allow-insecure-loopback",
        ],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect_err("relative production storage must fail");
    assert!(matches!(relative, RelayV2ConfigError::StorageInvalid(_)));
    assert_eq!(relative.code(), "relay.config.storage_invalid");

    let health = load(
        &[
            "agentdeck-relay",
            "--health-bind",
            "0.0.0.0:8444",
            "--allow-insecure-loopback",
        ],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect_err("health listener must stay loopback-only");
    assert!(matches!(health, RelayV2ConfigError::HealthNonLoopback));
    assert_eq!(health.code(), "relay.config.health_non_loopback");
}

#[test]
fn insecure_and_proxy_transport_modes_are_loopback_only_and_mutually_exclusive() {
    let temp = tempfile::tempdir().expect("tempdir");
    let insecure_public = load(
        &[
            "agentdeck-relay",
            "--bind",
            "0.0.0.0:8443",
            "--allow-insecure-loopback",
        ],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect_err("non-loopback plaintext must fail");
    assert!(matches!(insecure_public, RelayV2ConfigError::TlsRequired));
    assert_eq!(insecure_public.code(), "relay.transport.tls_required");

    let proxy_public = load(
        &["agentdeck-relay", "--bind", "0.0.0.0:8443", "--proxy-mode"],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect_err("proxy mode must bind loopback");
    assert!(matches!(proxy_public, RelayV2ConfigError::ProxyNonLoopback));
    assert_eq!(
        proxy_public.code(),
        "relay.transport.proxy_requires_loopback"
    );

    let proxy = load(
        &["agentdeck-relay", "--proxy-mode"],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect("loopback proxy mode");
    assert_eq!(proxy.transport, RelayV2TransportMode::ProxyLoopback);

    let conflict = load(
        &[
            "agentdeck-relay",
            "--proxy-mode",
            "--allow-insecure-loopback",
        ],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect_err("transport opt-ins are mutually exclusive");
    assert!(matches!(conflict, RelayV2ConfigError::TransportConflict));
}

#[test]
fn manually_constructed_server_config_cannot_bypass_transport_or_health_gates() {
    let temp = tempfile::tempdir().expect("tempdir");
    let base = RelayV2ServerConfig {
        bind: "127.0.0.1:8443".parse().unwrap(),
        health_bind: "127.0.0.1:8444".parse().unwrap(),
        store: RelayV2StoreSettings::new(temp.path().join("relay.db")),
        transport: RelayV2TransportMode::InsecureLoopback,
        admin: None,
        log_level: "info".to_owned(),
    };
    base.validate().expect("valid manual loopback config");

    let mut insecure_public = base.clone();
    insecure_public.bind = "0.0.0.0:8443".parse().unwrap();
    let error = insecure_public
        .validate()
        .expect_err("manual insecure public bind must fail");
    assert!(matches!(error, RelayV2ConfigError::TlsRequired));

    let mut proxy_public = base.clone();
    proxy_public.bind = "0.0.0.0:8443".parse().unwrap();
    proxy_public.transport = RelayV2TransportMode::ProxyLoopback;
    let error = proxy_public
        .validate()
        .expect_err("manual proxy public bind must fail");
    assert!(matches!(error, RelayV2ConfigError::ProxyNonLoopback));

    let mut public_health = base.clone();
    public_health.health_bind = "0.0.0.0:8444".parse().unwrap();
    let error = public_health
        .validate()
        .expect_err("manual public health bind must fail");
    assert!(matches!(error, RelayV2ConfigError::HealthNonLoopback));

    let mut relative_storage = base;
    relative_storage.store = RelayV2StoreSettings::new(PathBuf::from("relative/relay.db"));
    let error = relative_storage
        .validate()
        .expect_err("manual relative storage must fail");
    assert!(matches!(error, RelayV2ConfigError::StorageInvalid(_)));
}

#[cfg(not(feature = "tls"))]
#[test]
fn manually_constructed_direct_tls_requires_tls_feature() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = RelayV2ServerConfig {
        bind: "0.0.0.0:8443".parse().unwrap(),
        health_bind: "127.0.0.1:8444".parse().unwrap(),
        store: RelayV2StoreSettings::new(temp.path().join("relay.db")),
        transport: RelayV2TransportMode::DirectTls(agentdeck_relay::config::RelayV2TlsPaths {
            cert: PathBuf::from("/tmp/cert.pem"),
            key: PathBuf::from("/tmp/key.pem"),
        }),
        admin: None,
        log_level: "info".to_owned(),
    };
    let error = config
        .validate()
        .expect_err("manual DirectTls must fail without tls feature");
    assert!(matches!(error, RelayV2ConfigError::TlsFeatureMissing));
}

#[test]
fn tls_pair_must_be_complete() {
    let temp = tempfile::tempdir().expect("tempdir");
    let error = load(
        &["agentdeck-relay", "--tls-cert", "/tmp/relay-cert.pem"],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect_err("partial TLS paths must fail");

    assert!(matches!(error, RelayV2ConfigError::TlsPartial));
    assert_eq!(error.code(), "relay.config.tls_partial");
}

#[test]
fn higher_priority_partial_tls_pair_is_not_completed_from_a_lower_layer() {
    let temp = tempfile::tempdir().expect("tempdir");
    let cli_partial = load(
        &["agentdeck-relay", "--tls-cert", "/cli/relay-cert.pem"],
        &env(&[("AGENTDECK_RELAY_TLS_KEY", "/env/relay-key.pem")]),
        temp.path(),
    )
    .expect_err("CLI cert must not be paired with an env key");
    assert!(matches!(cli_partial, RelayV2ConfigError::TlsPartial));

    let config_path = temp.path().join("lower.toml");
    std::fs::write(
        &config_path,
        format!(
            "storage = {:?}\ntls_key = \"/file/relay-key.pem\"\n",
            temp.path().join("relay.db")
        ),
    )
    .expect("write lower config");
    let env_partial = load(
        &["agentdeck-relay", "--config", config_path.to_str().unwrap()],
        &env(&[("AGENTDECK_RELAY_TLS_CERT", "/env/relay-cert.pem")]),
        temp.path(),
    )
    .expect_err("env cert must not be paired with a file key");
    assert!(matches!(env_partial, RelayV2ConfigError::TlsPartial));
}

#[cfg(not(feature = "tls"))]
#[test]
fn tls_paths_fail_closed_when_binary_lacks_tls_feature() {
    let temp = tempfile::tempdir().expect("tempdir");
    let error = load(
        &[
            "agentdeck-relay",
            "--bind",
            "0.0.0.0:8443",
            "--tls-cert",
            "/tmp/relay-cert.pem",
            "--tls-key",
            "/tmp/relay-key.pem",
        ],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect_err("TLS configuration must never fall back to plaintext");

    assert!(matches!(error, RelayV2ConfigError::TlsFeatureMissing));
    assert_eq!(error.code(), "relay.transport.tls_feature_missing");
}

#[cfg(feature = "tls")]
#[test]
fn complete_tls_paths_select_direct_tls_without_opening_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = load(
        &[
            "agentdeck-relay",
            "--bind",
            "0.0.0.0:8443",
            "--tls-cert",
            "/tmp/relay-cert.pem",
            "--tls-key",
            "/tmp/relay-key.pem",
        ],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect("config layer only exposes paths; TLS module validates keypair");

    assert_eq!(
        config.transport,
        RelayV2TransportMode::DirectTls(RelayV2TlsPaths {
            cert: PathBuf::from("/tmp/relay-cert.pem"),
            key: PathBuf::from("/tmp/relay-key.pem"),
        })
    );
}

#[cfg(feature = "tls")]
#[test]
fn complete_tls_pair_is_selected_atomically_by_layer_priority() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = temp.path().join("relay.toml");
    std::fs::write(
        &config_path,
        format!(
            "storage = {:?}\ntls_cert = \"/file/cert.pem\"\ntls_key = \"/file/key.pem\"\n",
            temp.path().join("relay.db")
        ),
    )
    .expect("write config");
    let environment = env(&[
        ("AGENTDECK_RELAY_TLS_CERT", "/env/cert.pem"),
        ("AGENTDECK_RELAY_TLS_KEY", "/env/key.pem"),
    ]);

    let env_selected = load(
        &["agentdeck-relay", "--config", config_path.to_str().unwrap()],
        &environment,
        temp.path(),
    )
    .expect("complete env pair overrides complete file pair");
    assert_eq!(
        env_selected.transport,
        RelayV2TransportMode::DirectTls(RelayV2TlsPaths {
            cert: PathBuf::from("/env/cert.pem"),
            key: PathBuf::from("/env/key.pem"),
        })
    );

    let cli_selected = load(
        &[
            "agentdeck-relay",
            "--config",
            config_path.to_str().unwrap(),
            "--tls-cert",
            "/cli/cert.pem",
            "--tls-key",
            "/cli/key.pem",
        ],
        &environment,
        temp.path(),
    )
    .expect("complete CLI pair overrides complete env pair");
    assert_eq!(
        cli_selected.transport,
        RelayV2TransportMode::DirectTls(RelayV2TlsPaths {
            cert: PathBuf::from("/cli/cert.pem"),
            key: PathBuf::from("/cli/key.pem"),
        })
    );
}

#[cfg(feature = "tls")]
#[test]
fn relative_file_tls_paths_resolve_from_config_parent_but_storage_stays_strict() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_dir = temp.path().join("nested");
    std::fs::create_dir(&config_dir).expect("create config dir");
    let config_path = config_dir.join("relay.toml");
    std::fs::write(
        &config_path,
        format!(
            "storage = {:?}\ntls_cert = \"cert.pem\"\ntls_key = \"key.pem\"\n",
            temp.path().join("relay.db")
        ),
    )
    .expect("write relative TLS config");

    let config = load(
        &["agentdeck-relay", "--config", config_path.to_str().unwrap()],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect("relative TLS paths are anchored at the config parent");
    assert_eq!(
        config.transport,
        RelayV2TransportMode::DirectTls(RelayV2TlsPaths {
            cert: config_dir.join("cert.pem"),
            key: config_dir.join("key.pem"),
        })
    );

    std::fs::write(
        &config_path,
        "storage = \"relative.db\"\nallow_insecure_loopback = true\n",
    )
    .expect("write relative storage config");
    let storage_error = load(
        &["agentdeck-relay", "--config", config_path.to_str().unwrap()],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect_err("relative storage must not inherit TLS path resolution semantics");
    assert!(matches!(
        storage_error,
        RelayV2ConfigError::StorageInvalid(_)
    ));
}

#[test]
fn invalid_env_and_unknown_toml_fields_fail_instead_of_falling_back() {
    let temp = tempfile::tempdir().expect("tempdir");
    let invalid_bool = load(
        &["agentdeck-relay"],
        &env(&[("AGENTDECK_RELAY_ALLOW_INSECURE_LOOPBACK", "perhaps")]),
        temp.path(),
    )
    .expect_err("invalid security boolean must not silently become false");
    assert!(matches!(
        invalid_bool,
        RelayV2ConfigError::InvalidEnvironment { .. }
    ));

    let config_path = temp.path().join("unknown.toml");
    std::fs::write(
        &config_path,
        format!(
            "storage = {:?}\nallow_insecure_loopback = true\nunknown = \"value\"\n",
            temp.path().join("relay.db")
        ),
    )
    .expect("write config");
    let unknown = load(
        &["agentdeck-relay", "--config", config_path.to_str().unwrap()],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect_err("unknown TOML keys must fail closed");
    assert!(matches!(
        unknown,
        RelayV2ConfigError::ConfigFileParse { .. }
    ));
}

#[test]
fn admin_configuration_is_atomic_strict_and_requires_a_secure_transport_mode() {
    let temp = tempfile::tempdir().expect("tempdir");
    let socket = temp.path().join("relay-admin.sock");
    let pin = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let complete = load(
        &[
            "agentdeck-relay",
            "--proxy-mode",
            "--admin-socket",
            socket.to_str().unwrap(),
            "--public-wss-url",
            "wss://relay.example.test/",
            "--spki-pin",
            &pin,
        ],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect("complete proxy admin config");
    let admin = complete.admin.expect("admin enabled");
    assert_eq!(admin.socket_path, socket);
    assert_eq!(admin.public_wss_url, "wss://relay.example.test/");
    assert_eq!(admin.spki_pins, vec![[7; 32]]);

    let partial = load(
        &[
            "agentdeck-relay",
            "--proxy-mode",
            "--admin-socket",
            temp.path().join("partial.sock").to_str().unwrap(),
        ],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect_err("partial admin group fails closed");
    assert!(matches!(partial, RelayV2ConfigError::AdminPartial));

    let insecure = load(
        &[
            "agentdeck-relay",
            "--allow-insecure-loopback",
            "--admin-socket",
            temp.path().join("insecure.sock").to_str().unwrap(),
            "--public-wss-url",
            "wss://relay.example.test/",
            "--spki-pin",
            &pin,
        ],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect_err("plaintext development listener cannot expose enrollment");
    assert!(matches!(
        insecure,
        RelayV2ConfigError::AdminRequiresSecureTransport
    ));
}

#[test]
fn admin_url_and_pin_parser_rejects_ambiguous_or_malformed_values() {
    let temp = tempfile::tempdir().expect("tempdir");
    let socket = temp.path().join("relay-admin.sock");
    let pin = URL_SAFE_NO_PAD.encode([9_u8; 32]);
    for invalid_url in [
        "ws://relay.example.test/",
        "wss://user@relay.example.test/",
        "wss://relay.example.test/v2",
        "wss://relay.example.test/?secret=1",
    ] {
        let error = load(
            &[
                "agentdeck-relay",
                "--proxy-mode",
                "--admin-socket",
                socket.to_str().unwrap(),
                "--public-wss-url",
                invalid_url,
                "--spki-pin",
                &pin,
            ],
            &BTreeMap::new(),
            temp.path(),
        )
        .expect_err("invalid public WSS URL");
        assert!(matches!(
            error,
            RelayV2ConfigError::AdminInvalid {
                field: "public_wss_url"
            }
        ));
    }

    let malformed = load(
        &[
            "agentdeck-relay",
            "--proxy-mode",
            "--admin-socket",
            socket.to_str().unwrap(),
            "--public-wss-url",
            "wss://relay.example.test/",
            "--spki-pin",
            "AA",
        ],
        &BTreeMap::new(),
        temp.path(),
    )
    .expect_err("pin must decode to exactly 32 bytes");
    assert!(matches!(
        malformed,
        RelayV2ConfigError::AdminInvalid { field: "spki_pins" }
    ));
}

#[test]
fn admin_fields_follow_cli_over_env_over_toml_per_field() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = temp.path().join("relay.toml");
    let file_pin = URL_SAFE_NO_PAD.encode([0x11_u8; 32]);
    let env_pin = URL_SAFE_NO_PAD.encode([0x22_u8; 32]);
    std::fs::write(
        &config_path,
        format!(
            "proxy_mode = true\nadmin_socket = {:?}\npublic_wss_url = \"wss://file.example.test/\"\nspki_pins = [{:?}]\n",
            temp.path().join("file.sock"),
            file_pin,
        ),
    )
    .expect("write admin config");
    let cli_socket = temp.path().join("cli.sock");
    let environment = env(&[
        ("AGENTDECK_RELAY_PUBLIC_WSS_URL", "wss://env.example.test/"),
        ("AGENTDECK_RELAY_SPKI_PINS", &env_pin),
    ]);
    let config = load(
        &[
            "agentdeck-relay",
            "--config",
            config_path.to_str().unwrap(),
            "--admin-socket",
            cli_socket.to_str().unwrap(),
        ],
        &environment,
        temp.path(),
    )
    .expect("admin fields merge independently");
    let admin = config.admin.expect("admin config");
    assert_eq!(admin.socket_path, cli_socket);
    assert_eq!(admin.public_wss_url, "wss://env.example.test/");
    assert_eq!(admin.spki_pins, vec![[0x22; 32]]);
}
