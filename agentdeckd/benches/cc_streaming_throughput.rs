use agentdeck_protocol::{ClaudeCodePermissionMode, SessionId};
use agentdeckd::claude_code::translate::ClaudeCodeTranslator;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn bench(c: &mut Criterion) {
    let session_id = SessionId("bench".into());
    // Synthetic assistant text deltas — mirrors the CC wire shape for text content.
    let lines: Vec<String> = (0..1000)
        .map(|i| {
            format!(
                r#"{{"type":"assistant","message":{{"content":[{{"type":"text","text":"delta {} "}}]}}}}"#,
                i
            )
        })
        .collect();
    let total_bytes: usize = lines.iter().map(|l| l.len()).sum();

    let mut group = c.benchmark_group("cc_streaming");
    group.throughput(Throughput::Bytes(total_bytes as u64));
    group.bench_function("translate_1000_lines", |b| {
        b.iter(|| {
            let mut tr = ClaudeCodeTranslator::new(
                session_id.clone(),
                ClaudeCodePermissionMode::BypassPermissions,
            );
            for line in &lines {
                let _out = tr.translate_line(black_box(line));
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
