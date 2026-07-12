// agentdeck-relay/src/main.rs
//! `agentdeck-relay` 二进制：加载配置 + 传输门禁 + tracing init + `server::serve`。
//! `--selfcheck`：只加载/校验配置、构造 store/relay，不起监听，打印 ok 后退出 0
//! （用于部署前快速验证配置/依赖装配是否正常，不做网络 IO）。
//!
//! 本文件只在 `server` feature 打开时编译为真正的二进制入口——`[[bin]]` 在
//! `Cargo.toml` 里声明了 `required-features = ["server"]`，所以
//! `cargo build -p agentdeck-relay`（无 `--features server`）根本不会编译到
//! 这个 target；下面的 `#[cfg(not(feature = "server"))]` 分支是防御性兜底
//! （例如有人显式 `--bin agentdeck-relay` 却忘了带 feature 时给出清晰提示），
//! 正常路径下不会被触达。

#[cfg(feature = "server")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let admin_output = agentdeck_relay::v2::admin::command::execute_admin_cli(
        args.iter().cloned(),
        std::env::var_os("AGENTDECK_RELAY_ADMIN_SOCKET").map(std::path::PathBuf::from),
    )
    .await;
    if let Err(error) = &admin_output {
        eprintln!("{}", error.code());
        std::process::exit(2);
    }
    if let Some(output) = admin_output.ok().flatten() {
        println!("{}", output.json);
        if !output.success {
            std::process::exit(2);
        }
        return Ok(());
    }
    let selfcheck = args.iter().any(|a| a == "--selfcheck");

    let config = agentdeck_relay::config::RelayConfig::load()?;
    config.validate_transport_gate()?;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(config.log_level.clone()));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // `--selfcheck`：不落盘真实数据文件（避免每次 selfcheck 污染 CWD/部署目录）——
    // 走 in-memory SQLite，只验证配置/依赖装配是否正常，不做网络 IO。
    let store = if selfcheck {
        agentdeck_relay::SqliteRelayStore::open_in_memory()
            .map_err(|e| format!("selfcheck: failed to open in-memory sqlite store: {e}"))?
    } else {
        if let Some(parent) = config.storage_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "failed to create storage directory {}: {e}",
                    parent.display()
                )
            })?;
        }
        agentdeck_relay::SqliteRelayStore::open(&config.storage_path).map_err(|e| {
            format!(
                "failed to open sqlite store at {}: {e}",
                config.storage_path.display()
            )
        })?
    };

    let relay = agentdeck_relay::FakeRelay::start_with_all(
        store.clone(),
        config.req_origin_ttl_ms as i64,
        config.conv_buffer_cap,
    );

    if selfcheck {
        println!("relay selfcheck ok");
        return Ok(());
    }

    tracing::info!(bind = %config.bind, storage_path = %config.storage_path.display(), "relay listening");
    agentdeck_relay::server::serve(config, store, relay).await?;
    Ok(())
}

#[cfg(not(feature = "server"))]
fn main() {
    eprintln!("agentdeck-relay binary requires --features server");
    std::process::exit(1);
}
