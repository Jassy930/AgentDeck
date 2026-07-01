use agentdeck_protocol::{AgentKind, HistoryListItem, ThreadId};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn make_5k() -> Vec<HistoryListItem> {
    (0..5000)
        .map(|i| HistoryListItem {
            thread_id: ThreadId(format!("uuid-{}", i)),
            agent_kind: if i % 2 == 0 {
                AgentKind::Codex
            } else {
                AgentKind::ClaudeCode
            },
            title: Some(format!("session {}", i)),
            cwd: PathBuf::from(format!("/proj/{}", i % 100)),
            last_active_ms: 1_700_000_000_000 + (i as u64),
            archived: false,
        })
        .collect()
}

fn group_by_cwd(items: &[HistoryListItem]) -> BTreeMap<PathBuf, Vec<&HistoryListItem>> {
    let mut g: BTreeMap<PathBuf, Vec<&HistoryListItem>> = BTreeMap::new();
    for it in items {
        g.entry(it.cwd.clone()).or_default().push(it);
    }
    g
}

fn bench(c: &mut Criterion) {
    let items = make_5k();
    c.bench_function("history_5k_group_by_cwd", |b| {
        b.iter(|| black_box(group_by_cwd(black_box(&items))));
    });
    c.bench_function("history_5k_filter_codex_only", |b| {
        b.iter(|| {
            let filtered: Vec<_> = items
                .iter()
                .filter(|i| i.agent_kind == AgentKind::Codex)
                .collect();
            black_box(filtered)
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
