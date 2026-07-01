use agentdeck_protocol::{ClaudeCodePermissionMode, SessionId};
use agentdeckd::claude_code::translate::ClaudeCodeTranslator;
use agentdeckd::codex::translate::CodexTranslator;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench(c: &mut Criterion) {
    let cc_line = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"x"}]}}"#;
    let codex_line = r#"{"jsonrpc":"2.0","method":"codex/event","params":{"id":"e","msg":{"type":"agent_message","delta":"x"}}}"#;

    c.bench_function("8_concurrent_translators_100_lines_each", |b| {
        b.iter(|| {
            let mut translators_cc: Vec<_> = (0..4)
                .map(|i| {
                    ClaudeCodeTranslator::new(
                        SessionId(format!("cc-{}", i)),
                        ClaudeCodePermissionMode::BypassPermissions,
                    )
                })
                .collect();
            let mut translators_codex: Vec<_> = (0..4)
                .map(|i| CodexTranslator::new(SessionId(format!("codex-{}", i)), None))
                .collect();
            for _ in 0..100 {
                for tr in translators_cc.iter_mut() {
                    let _ = tr.translate_line(black_box(cc_line));
                }
                for tr in translators_codex.iter_mut() {
                    let _ = tr.translate_line(black_box(codex_line));
                }
            }
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
