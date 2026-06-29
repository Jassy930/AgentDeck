mod output;

use clap::{Parser, Subcommand};
use output::{render, CliError};

#[derive(Parser)]
#[command(name = "agentdeck", about = "AgentDeck unified interface CLI")]
struct Cli {
    /// AgentDeck profile（仅影响 AgentDeck 自管理数据目录）
    #[arg(long, global = true, default_value = "stable")]
    profile: String,
    /// 覆盖数据目录（优先于 profile）
    #[arg(long, global = true)]
    data_dir: Option<String>,
    /// 人读 pretty 输出（E2E 不依赖）
    #[arg(long, global = true)]
    pretty: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 协议自省
    Protocol {
        #[command(subcommand)]
        what: ProtocolCmd,
    },
}

#[derive(Subcommand)]
enum ProtocolCmd {
    /// 输出版本化 JSON Schema
    Schema,
    /// 输出协议版本号
    Version,
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Protocol { what } => match what {
            ProtocolCmd::Schema => {
                // schema 始终 pretty（它是文档产物），与 drift 快照一致
                println!("{}", serde_json::to_string_pretty(&agentdeck_protocol::protocol_schema()).expect("json"));
                Ok(())
            }
            ProtocolCmd::Version => {
                let v = serde_json::json!({ "protocolVersion": agentdeck_protocol::PROTOCOL_VERSION });
                println!("{}", render(&v, cli.pretty));
                Ok(())
            }
        },
    }
}

fn main() {
    let cli = Cli::parse();
    let pretty = cli.pretty;
    if let Err(err) = run(cli) {
        eprintln!("agentdeck: {}", err.message());
        println!("{}", render(&output::error_envelope(&err), pretty));
        std::process::exit(err.exit_code());
    }
}
