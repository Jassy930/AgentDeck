//! Codex history adapter backed by the official app-server thread APIs.
//!
//! Each operation owns a short-lived app-server connection: initialize,
//! issue bounded request/response calls, then terminate the child. The live
//! session adapter and this module share the same process and JSONL transport
//! primitives in `app_server.rs`.

use crate::codex::app_server::{SHORT_LIVED_SHUTDOWN_TIMEOUT, ShortLivedAppServer};
use crate::codex::translate::history_item_to_agent_item;
use agentdeck_protocol::{
    AgentKind, HistoryListItem, HistoryReadResponse, HistoryTurn, ProtocolError, ThreadId,
    effective_history_list_limit,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

const HISTORY_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const DECODE_DETAILS_WITHHELD_NOTE: &str =
    "vendor response details withheld by the vendor-token boundary";

fn history_work_timeout() -> Duration {
    // Reserve enough of the public 30-second deadline to SIGKILL the process
    // group and wait for the direct child. This keeps cleanup explicit even
    // when the history operation itself times out.
    HISTORY_OPERATION_TIMEOUT.saturating_sub(SHORT_LIVED_SHUTDOWN_TIMEOUT)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ThreadListPage {
    data: Vec<ThreadListEntry>,
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ThreadListEntry {
    id: String,
    #[serde(default)]
    name: Option<String>,
    preview: String,
    cwd: PathBuf,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct ThreadReadResult {
    thread: ThreadReadThread,
}

#[derive(Debug, Deserialize)]
struct ThreadReadThread {
    id: String,
    turns: Vec<ThreadReadTurn>,
}

#[derive(Debug, Deserialize)]
struct ThreadReadTurn {
    items: Vec<Value>,
}

fn decode_error(operation: &str, _error: serde_json::Error) -> ProtocolError {
    ProtocolError {
        code: "codex-history-decode-failed".into(),
        message: format!(
            "decode Codex {operation} response failed; {DECODE_DETAILS_WITHHELD_NOTE}"
        ),
        diagnostic_ref: None,
    }
}

fn history_timeout_error(operation: &str) -> ProtocolError {
    ProtocolError {
        code: "codex-history-timeout".into(),
        message: format!(
            "Codex history {operation} exceeded the {} second operation deadline",
            HISTORY_OPERATION_TIMEOUT.as_secs()
        ),
        diagnostic_ref: None,
    }
}

async fn with_history_deadline<T>(
    operation: &str,
    timeout: Duration,
    future: impl Future<Output = Result<T, ProtocolError>>,
) -> Result<T, ProtocolError> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| history_timeout_error(operation))?
}

fn runtime_cwd() -> Result<PathBuf, ProtocolError> {
    std::env::current_dir().map_err(|error| ProtocolError {
        code: "codex-history-cwd-unavailable".into(),
        message: format!("resolve current directory for Codex history query: {error}"),
        diagnostic_ref: None,
    })
}

fn thread_list_params(cwd_filter: Option<&Path>, limit: usize, cursor: Option<&str>) -> Value {
    let mut params = json!({
        "archived": false,
        "limit": u32::try_from(limit).expect("AgentDeck history limit fits u32"),
        "sortDirection": "desc",
        "sortKey": "updated_at",
    });
    let object = params
        .as_object_mut()
        .expect("thread/list params literal is an object");
    if let Some(cwd) = cwd_filter {
        object.insert("cwd".into(), json!(cwd.to_string_lossy()));
    }
    if let Some(cursor) = cursor {
        object.insert("cursor".into(), json!(cursor));
    }
    params
}

fn last_active_ms(updated_at: i64) -> Result<u64, ProtocolError> {
    u64::try_from(updated_at)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or_else(|| ProtocolError {
            code: "codex-history-invalid-timestamp".into(),
            message: format!("thread/list returned invalid updatedAt={updated_at}"),
            diagnostic_ref: None,
        })
}

fn decode_thread_list_page(
    value: Value,
) -> Result<(Vec<HistoryListItem>, Option<String>), ProtocolError> {
    let page: ThreadListPage =
        serde_json::from_value(value).map_err(|error| decode_error("thread/list", error))?;
    let mut items = Vec::with_capacity(page.data.len());
    for thread in page.data {
        let title = thread
            .name
            .filter(|name| !name.trim().is_empty())
            .or_else(|| (!thread.preview.trim().is_empty()).then_some(thread.preview));
        items.push(HistoryListItem {
            thread_id: ThreadId(thread.id),
            agent_kind: AgentKind::Codex,
            title,
            cwd: thread.cwd,
            last_active_ms: last_active_ms(thread.updated_at)?,
            archived: false,
        });
    }
    Ok((items, page.next_cursor))
}

/// List non-archived interactive Codex threads, newest updated first.
/// `cwd_filter` is passed to app-server's exact-match `cwd` filter. Pages are
/// followed until the neutral AgentDeck limit is satisfied.
pub async fn list_history(
    cwd_filter: Option<&Path>,
    limit: Option<usize>,
) -> Result<Vec<HistoryListItem>, ProtocolError> {
    let cwd_filter = cwd_filter.map(Path::to_path_buf);
    let mut client = ShortLivedAppServer::spawn(&runtime_cwd()?)?;
    let result = with_history_deadline(
        "list",
        history_work_timeout(),
        list_history_inner(&mut client, cwd_filter, limit),
    )
    .await;
    client.shutdown().await;
    result.map_err(|error| client.enrich_error(error))
}

async fn list_history_inner(
    client: &mut ShortLivedAppServer,
    cwd_filter: Option<PathBuf>,
    limit: Option<usize>,
) -> Result<Vec<HistoryListItem>, ProtocolError> {
    let target = effective_history_list_limit(limit);
    client.initialize().await?;

    let mut items = Vec::with_capacity(target);
    let mut cursor: Option<String> = None;
    loop {
        let remaining = target - items.len();
        let result = client
            .request(
                "thread/list",
                thread_list_params(cwd_filter.as_deref(), remaining, cursor.as_deref()),
            )
            .await?;
        let (mut page_items, next_cursor) = decode_thread_list_page(result)?;
        let page_was_empty = page_items.is_empty();
        page_items.truncate(remaining);
        items.append(&mut page_items);

        if items.len() >= target || page_was_empty || next_cursor.is_none() {
            break;
        }
        if next_cursor == cursor {
            return Err(ProtocolError {
                code: "codex-history-pagination-stalled".into(),
                message: "thread/list returned the same pagination cursor twice".into(),
                diagnostic_ref: None,
            });
        }
        cursor = next_cursor;
    }
    Ok(items)
}

fn decode_thread_read(
    value: Value,
    requested_thread_id: &ThreadId,
) -> Result<HistoryReadResponse, ProtocolError> {
    let response: ThreadReadResult =
        serde_json::from_value(value).map_err(|error| decode_error("thread/read", error))?;
    if response.thread.id != requested_thread_id.0 {
        return Err(ProtocolError {
            code: "codex-history-thread-mismatch".into(),
            message: format!(
                "thread/read returned id={} for requested id={}",
                response.thread.id, requested_thread_id.0
            ),
            diagnostic_ref: None,
        });
    }
    let turns = response
        .thread
        .turns
        .into_iter()
        .map(|turn| HistoryTurn {
            items: turn.items.iter().map(history_item_to_agent_item).collect(),
        })
        .collect();
    Ok(HistoryReadResponse {
        thread_id: requested_thread_id.clone(),
        agent_kind: AgentKind::Codex,
        turns,
    })
}

/// Read all persisted turns/items for one Codex thread. The item payloads are
/// mapped through the same completed-item translator as live sessions.
pub async fn read_history(thread_id: &ThreadId) -> Result<HistoryReadResponse, ProtocolError> {
    let mut client = ShortLivedAppServer::spawn(&runtime_cwd()?)?;
    let result = with_history_deadline(
        "read",
        history_work_timeout(),
        read_history_inner(&mut client, thread_id.clone()),
    )
    .await;
    client.shutdown().await;
    result.map_err(|error| client.enrich_error(error))
}

async fn read_history_inner(
    client: &mut ShortLivedAppServer,
    thread_id: ThreadId,
) -> Result<HistoryReadResponse, ProtocolError> {
    client.initialize().await?;
    let result = client
        .request(
            "thread/read",
            json!({ "threadId": thread_id.0.clone(), "includeTurns": true }),
        )
        .await?;
    decode_thread_read(result, &thread_id)
}

/// Archive is not exposed yet; return a structured error.
pub async fn archive(_thread_id: &ThreadId) -> Result<(), ProtocolError> {
    Err(ProtocolError {
        code: "codex-archive-not-supported".into(),
        message: "Codex thread archive not exposed in v0.2".into(),
        diagnostic_ref: None,
    })
}

/// Unarchive is not exposed yet.
pub async fn unarchive(_thread_id: &ThreadId) -> Result<(), ProtocolError> {
    Err(ProtocolError {
        code: "codex-unarchive-not-supported".into(),
        message: "Codex thread unarchive not exposed in v0.2".into(),
        diagnostic_ref: None,
    })
}

/// Rename is not exposed yet.
pub async fn rename(_thread_id: &ThreadId, _title: &str) -> Result<(), ProtocolError> {
    Err(ProtocolError {
        code: "codex-rename-not-supported".into(),
        message: "Codex thread rename not exposed in v0.2".into(),
        diagnostic_ref: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentdeck_protocol::{AgentItem, DiffStatus, ShellStatus};

    fn thread_fixture(id: &str, name: Option<&str>, preview: &str, updated_at: i64) -> Value {
        json!({
            "agentNickname": null,
            "agentRole": null,
            "cliVersion": "0.145.0",
            "createdAt": 10,
            "cwd": "/tmp/project",
            "ephemeral": false,
            "forkedFromId": null,
            "gitInfo": null,
            "id": id,
            "modelProvider": "openai",
            "name": name,
            "parentThreadId": null,
            "path": null,
            "preview": preview,
            "recencyAt": updated_at,
            "sessionId": "session-1",
            "source": "vscode",
            "status": { "type": "notLoaded" },
            "threadSource": null,
            "turns": [],
            "updatedAt": updated_at,
        })
    }

    #[test]
    fn thread_list_params_match_official_filter_and_pagination_shape() {
        let params = thread_list_params(Some(Path::new("/tmp/project")), 25, Some("next-1"));
        assert_eq!(params["archived"], false);
        assert_eq!(params["cwd"], "/tmp/project");
        assert_eq!(params["cursor"], "next-1");
        assert_eq!(params["limit"], 25);
        assert_eq!(params["sortKey"], "updated_at");
        assert_eq!(params["sortDirection"], "desc");
        assert!(params.get("sourceKinds").is_none());
        assert!(params.get("useStateDbOnly").is_none());
    }

    #[test]
    fn thread_list_response_maps_official_threads_to_neutral_items() {
        let response = json!({
            "backwardsCursor": "back-1",
            "data": [
                thread_fixture("thread-1", Some("Named thread"), "first prompt", 20),
                thread_fixture("thread-2", None, "preview fallback", 15),
            ],
            "nextCursor": "next-1",
        });
        let (items, cursor) = decode_thread_list_page(response).expect("decode list fixture");
        assert_eq!(cursor.as_deref(), Some("next-1"));
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].thread_id, ThreadId("thread-1".into()));
        assert_eq!(items[0].agent_kind, AgentKind::Codex);
        assert_eq!(items[0].title.as_deref(), Some("Named thread"));
        assert_eq!(items[0].cwd, PathBuf::from("/tmp/project"));
        assert_eq!(items[0].last_active_ms, 20_000);
        assert!(!items[0].archived);
        assert_eq!(items[1].title.as_deref(), Some("preview fallback"));
    }

    #[test]
    fn thread_list_rejects_negative_updated_timestamp() {
        let response = json!({
            "data": [thread_fixture("thread-1", None, "preview", -1)],
            "nextCursor": null,
        });
        let error = decode_thread_list_page(response).expect_err("negative timestamp must fail");
        assert_eq!(error.code, "codex-history-invalid-timestamp");
    }

    #[test]
    fn thread_list_decode_failure_withholds_vendor_value() {
        let secret = "sk-list-secret-must-not-cross-k9";
        let error = decode_thread_list_page(json!({
            "data": secret,
            "nextCursor": null
        }))
        .expect_err("invalid thread/list data shape must fail");

        assert_eq!(error.code, "codex-history-decode-failed");
        assert!(error.message.contains(DECODE_DETAILS_WITHHELD_NOTE));
        assert!(!error.message.contains(secret));
    }

    #[test]
    fn thread_read_reuses_live_item_mapping_and_preserves_turns() {
        let response = json!({
            "thread": {
                "cliVersion": "0.145.0",
                "createdAt": 10,
                "cwd": "/tmp/project",
                "ephemeral": false,
                "id": "thread-1",
                "modelProvider": "openai",
                "preview": "hello",
                "sessionId": "session-1",
                "source": "vscode",
                "status": { "type": "notLoaded" },
                "turns": [{
                    "id": "turn-1",
                    "itemsView": "full",
                    "status": "completed",
                    "items": [
                        {
                            "id": "user-1",
                            "type": "userMessage",
                            "content": [{ "type": "text", "text": "hello" }]
                        },
                        { "id": "agent-1", "type": "agentMessage", "text": "world" },
                        {
                            "id": "reason-1",
                            "type": "reasoning",
                            "summary": ["short summary"],
                            "content": ["long content"]
                        },
                        {
                            "id": "shell-1",
                            "type": "commandExecution",
                            "command": "pwd",
                            "commandActions": [],
                            "cwd": "/tmp/project",
                            "status": "completed",
                            "exitCode": 0,
                            "durationMs": 12
                        },
                        {
                            "id": "diff-1",
                            "type": "fileChange",
                            "status": "completed",
                            "changes": [
                                {
                                    "path": "README.md",
                                    "kind": { "type": "update", "move_path": null },
                                    "diff": "@@ -1 +1 @@"
                                },
                                {
                                    "path": "new.txt",
                                    "kind": { "type": "add" },
                                    "diff": "+new"
                                },
                                {
                                    "path": "old.txt",
                                    "kind": { "type": "delete" },
                                    "diff": "-old"
                                },
                                {
                                    "path": "before.txt",
                                    "kind": {
                                        "type": "update",
                                        "move_path": "after.txt"
                                    },
                                    "diff": ""
                                }
                            ]
                        },
                        { "id": "compact-1", "type": "contextCompaction" }
                    ]
                }],
                "updatedAt": 20
            }
        });
        let history = decode_thread_read(response, &ThreadId("thread-1".into()))
            .expect("decode read fixture");
        assert_eq!(history.agent_kind, AgentKind::Codex);
        assert_eq!(history.turns.len(), 1);
        let items = &history.turns[0].items;
        assert!(matches!(
            &items[0],
            AgentItem::UserMessage { text, .. } if text == "hello"
        ));
        assert!(matches!(
            &items[1],
            AgentItem::AssistantMessage { text, .. } if text == "world"
        ));
        assert!(matches!(
            &items[2],
            AgentItem::Reasoning { text, .. } if text == "short summary"
        ));
        assert!(matches!(
            &items[3],
            AgentItem::Shell {
                command,
                status: ShellStatus::Completed,
                exit_code: Some(0),
                duration_ms: Some(12),
                ..
            } if command == "pwd"
        ));
        assert!(matches!(
            &items[4],
            AgentItem::Diff { files, .. }
                if files.len() == 4
                    && matches!(files[0].status, DiffStatus::Modified)
                    && matches!(files[1].status, DiffStatus::Added)
                    && matches!(files[2].status, DiffStatus::Deleted)
                    && matches!(files[3].status, DiffStatus::Renamed)
                    && files[3].path == PathBuf::from("after.txt")
        ));
        assert!(matches!(
            &items[5],
            AgentItem::Raw { raw_kind, .. } if raw_kind == "contextCompaction"
        ));
    }

    #[test]
    fn thread_read_rejects_mismatched_thread_id() {
        let response = json!({
            "thread": { "id": "other-thread", "turns": [] }
        });
        let error = decode_thread_read(response, &ThreadId("requested-thread".into()))
            .expect_err("mismatched id must fail");
        assert_eq!(error.code, "codex-history-thread-mismatch");
    }

    #[test]
    fn thread_read_decode_failure_withholds_vendor_value() {
        let secret = "sk-read-secret-must-not-cross-k9";
        let error = decode_thread_read(
            json!({
                "thread": {
                    "id": "thread-1",
                    "turns": secret
                }
            }),
            &ThreadId("thread-1".into()),
        )
        .expect_err("invalid thread/read turns shape must fail");

        assert_eq!(error.code, "codex-history-decode-failed");
        assert!(error.message.contains(DECODE_DETAILS_WITHHELD_NOTE));
        assert!(!error.message.contains(secret));
    }

    #[tokio::test]
    async fn operation_deadline_returns_history_specific_timeout() {
        let never = std::future::pending::<Result<(), ProtocolError>>();
        let error = with_history_deadline("list", Duration::ZERO, never)
            .await
            .expect_err("expired history operation must time out");
        assert_eq!(error.code, "codex-history-timeout");
        assert!(error.message.contains("history list"));
    }

    #[test]
    fn public_history_deadline_reserves_bounded_child_cleanup() {
        assert_eq!(
            history_work_timeout() + SHORT_LIVED_SHUTDOWN_TIMEOUT,
            HISTORY_OPERATION_TIMEOUT
        );
    }

    #[tokio::test]
    async fn gated_real_codex_list_and_read_smoke() {
        if std::env::var("AGENTDECK_E2E").as_deref() != Ok("1") {
            eprintln!("SKIP gated_real_codex_list_and_read_smoke: AGENTDECK_E2E != 1");
            return;
        }
        if which::which("codex").is_err() {
            eprintln!("SKIP gated_real_codex_list_and_read_smoke: codex not in PATH");
            return;
        }
        let items = list_history(None, Some(3))
            .await
            .expect("real Codex thread/list should succeed");
        assert!(items.len() <= 3);
        assert!(items.iter().all(|item| item.agent_kind == AgentKind::Codex));
        if let Some(first) = items.first() {
            let detail = read_history(&first.thread_id)
                .await
                .expect("real Codex thread/read should succeed");
            assert_eq!(detail.thread_id, first.thread_id);
            assert_eq!(detail.agent_kind, AgentKind::Codex);
        }
    }

    #[tokio::test]
    async fn archive_returns_structured_error() {
        let err = archive(&ThreadId("x".into())).await.unwrap_err();
        assert_eq!(err.code, "codex-archive-not-supported");
    }

    #[tokio::test]
    async fn unarchive_returns_structured_error() {
        let err = unarchive(&ThreadId("x".into())).await.unwrap_err();
        assert_eq!(err.code, "codex-unarchive-not-supported");
    }

    #[tokio::test]
    async fn rename_returns_structured_error() {
        let err = rename(&ThreadId("x".into()), "name").await.unwrap_err();
        assert_eq!(err.code, "codex-rename-not-supported");
    }
}
