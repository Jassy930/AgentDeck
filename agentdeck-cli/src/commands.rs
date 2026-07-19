//! 不连接 Runtime UDS 的本地/one-shot 命令。

use crate::output::{CliError, render};
use crate::transport;

pub fn handle_diagnostics_report(
    profile: &str,
    data_dir: Option<&str>,
    pretty: bool,
) -> Result<(), CliError> {
    let raw = transport::run_daemon_diagnostics_report(profile, data_dir).map_err(|error| {
        CliError::Transport {
            code: None,
            message: error.to_string(),
        }
    })?;
    let report: serde_json::Value = serde_json::from_str(&raw)?;
    println!("{}", render(&report, pretty));
    Ok(())
}

fn print_schema(schema: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(schema).expect("schema serialization is infallible")
    );
}

pub fn handle_protocol_schema() -> Result<(), CliError> {
    print_schema(&agentdeck_protocol::protocol_schema());
    Ok(())
}

pub fn handle_protocol_runtime_schema() -> Result<(), CliError> {
    print_schema(&agentdeck_protocol::runtime::runtime_schema());
    Ok(())
}

pub fn handle_protocol_relay_schema() -> Result<(), CliError> {
    print_schema(&agentdeck_protocol::relay_v2::relay_v2_schema());
    Ok(())
}

pub fn handle_protocol_e2ee_schema() -> Result<(), CliError> {
    print_schema(&agentdeck_protocol::e2ee::e2ee_schema());
    Ok(())
}

pub fn handle_protocol_version(pretty: bool) -> Result<(), CliError> {
    println!(
        "{}",
        render(
            &serde_json::json!({"protocolVersion": agentdeck_protocol::PROTOCOL_VERSION}),
            pretty,
        )
    );
    Ok(())
}
