//! `agentdeck-relay`：Relay v2 唯一生产入口。

#[cfg(feature = "server")]
#[tokio::main]
async fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if contains_legacy_v1_flag(&args) || contains_legacy_v1_environment() {
        exit_with("relay.v1.reset_required");
    }
    let admin_output = agentdeck_relay::v2::admin::command::execute_admin_cli(
        args.iter().cloned(),
        std::env::var_os("AGENTDECK_RELAY_ADMIN_SOCKET").map(std::path::PathBuf::from),
    )
    .await;
    match admin_output {
        Err(error) => exit_with(error.code()),
        Ok(Some(output)) => {
            println!("{}", output.json);
            if !output.success {
                std::process::exit(2);
            }
            return;
        }
        Ok(None) => {}
    }

    let selfcheck = args
        .iter()
        .any(|argument| argument == std::ffi::OsStr::new("--selfcheck"));
    let config = match agentdeck_relay::config::RelayV2ServerConfig::load() {
        Ok(config) => config,
        Err(error) => exit_with(error.code()),
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(config.log_level.clone()));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let result = if selfcheck {
        agentdeck_relay::v2::server::selfcheck(config).await
    } else {
        agentdeck_relay::v2::server::serve_until_signal(config).await
    };
    if let Err(error) = result {
        exit_with(error.code());
    }
}

#[cfg(feature = "server")]
fn contains_legacy_v1_flag(args: &[std::ffi::OsString]) -> bool {
    const REMOVED: &[&str] = &[
        "--bootstrap-secret",
        "--allow-plaintext",
        "--conv-buffer-cap",
        "--req-origin-ttl-ms",
    ];
    args.iter().any(|argument| {
        let argument = argument.as_encoded_bytes();
        REMOVED.iter().any(|flag| {
            let flag = flag.as_bytes();
            argument == flag
                || (argument.starts_with(flag) && argument.get(flag.len()) == Some(&b'='))
        })
    })
}

#[cfg(feature = "server")]
fn contains_legacy_v1_environment() -> bool {
    const REMOVED: &[&str] = &[
        "AGENTDECK_RELAY_BOOTSTRAP_SECRET",
        "AGENTDECK_RELAY_ALLOW_PLAINTEXT",
        "AGENTDECK_RELAY_CONV_BUFFER_CAP",
        "AGENTDECK_RELAY_REQ_ORIGIN_TTL_MS",
    ];
    REMOVED.iter().any(|name| std::env::var_os(name).is_some())
}

#[cfg(feature = "server")]
fn exit_with(code: &str) -> ! {
    eprintln!("{code}");
    std::process::exit(2);
}

#[cfg(not(feature = "server"))]
fn main() {
    eprintln!("agentdeck-relay binary requires --features server");
    std::process::exit(1);
}
