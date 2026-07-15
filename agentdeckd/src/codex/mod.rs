//! Codex adapter — translates codex app-server JSON-RPC into neutral
//! agent events. v2 protocol; N3 守护：本模块禁止 use claude_code::* 任何符号。
//! vendor thread id 只允许进入本模块的 typed state repository；common catalog
//! 只保存 neutral adapterStateKey。

pub mod adapter;
pub mod capabilities;
mod driver;
#[cfg(test)]
mod driver_tests;
pub mod history;
mod runtime_translate;
#[cfg(test)]
mod runtime_translate_tests;
mod state;
pub mod translate;

pub use adapter::CodexAdapter;

/// 真实录制 fixture 的 crate-unit-test 入口。保持 typed translator 私有，测试只取得
/// 中立 AdapterEvent 与 terminal；integration/public API 不暴露 vendor wire parser。
#[cfg(test)]
pub(crate) fn translate_runtime_fixture_for_test(
    content: &str,
) -> Result<
    (
        Vec<crate::agent::AdapterEvent>,
        Vec<agentdeck_protocol::TurnSummary>,
    ),
    agentdeck_protocol::ProtocolError,
> {
    use runtime_translate::{CodexRuntimeOutput, CodexRuntimeTranslator};

    let mut translator = CodexRuntimeTranslator::new();
    let mut events = Vec::new();
    let mut terminals = Vec::new();
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        for output in translator.translate_line(line)? {
            match output {
                CodexRuntimeOutput::Event(event) => events.push(event),
                // Production driver records modeled diagnostics out-of-band; the fixture
                // helper intentionally exposes only durable neutral events and terminals.
                CodexRuntimeOutput::Diagnostic { .. } => {}
                CodexRuntimeOutput::TurnComplete(summary) => terminals.push(summary),
                CodexRuntimeOutput::Approval { .. } => {
                    return Err(agentdeck_protocol::ProtocolError {
                        code: "codex-fixture-unexpected-approval".to_owned(),
                        message: "Codex runtime fixture unexpectedly requested approval".to_owned(),
                        diagnostic_ref: None,
                    });
                }
            }
        }
    }
    Ok((events, terminals))
}
