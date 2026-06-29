use crate::output::{req, CliError};
use agentdeck_protocol::IpcMessage;

pub fn ping_request() -> IpcMessage {
    req("ping", None)
}

pub fn selfcheck_request() -> IpcMessage {
    req("selfcheck/logging", None)
}

pub fn diagnostics_request(limit: Option<u64>, since_seconds: Option<u64>, run_id: Option<String>) -> IpcMessage {
    let mut p = serde_json::Map::new();
    if let Some(l) = limit { p.insert("limit".into(), l.into()); }
    if let Some(s) = since_seconds { p.insert("sinceSeconds".into(), s.into()); }
    if let Some(r) = run_id { p.insert("runId".into(), r.into()); }
    req("diagnostics/report", if p.is_empty() { None } else { Some(p.into()) })
}

pub fn history_list_request(cwd: Option<String>, search: Option<String>, cursor: Option<String>, limit: Option<u64>) -> IpcMessage {
    let mut p = serde_json::Map::new();
    if let Some(c) = cwd { p.insert("cwd".into(), c.into()); }
    if let Some(s) = search { p.insert("searchTerm".into(), s.into()); }
    if let Some(c) = cursor { p.insert("cursor".into(), c.into()); }
    if let Some(l) = limit { p.insert("limit".into(), l.into()); }
    req("history/listThreads", if p.is_empty() { None } else { Some(p.into()) })
}

pub fn history_read_request(thread_id: &str) -> IpcMessage {
    req("history/readThread", Some(serde_json::json!({ "threadId": thread_id })))
}

pub fn history_manage_request(kind: &str, thread_id: &str, name: Option<&str>) -> IpcMessage {
    let mut p = serde_json::Map::new();
    p.insert("threadId".into(), thread_id.into());
    if let Some(n) = name { p.insert("name".into(), n.into()); }
    req(kind, Some(p.into()))
}

pub fn interpret_selfcheck(payload: &serde_json::Value) -> Result<(), CliError> {
    let ok = |k: &str| payload.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    if ok("recordOk") && ok("diagnosticOk") && ok("redactionOk") {
        Ok(())
    } else {
        Err(CliError::Session("selfcheck failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_list_request_omits_empty_payload() {
        let m = history_list_request(None, None, None, None);
        assert_eq!(m.kind, "history/listThreads");
        assert!(m.payload.is_none());
    }

    #[test]
    fn history_rename_request_carries_name() {
        let m = history_manage_request("history/renameThread", "t1", Some("New"));
        assert_eq!(m.payload.as_ref().unwrap()["threadId"], "t1");
        assert_eq!(m.payload.as_ref().unwrap()["name"], "New");
    }

    #[test]
    fn diagnostics_request_includes_filters() {
        let m = diagnostics_request(Some(10), Some(60), Some("run-1".into()));
        let p = m.payload.as_ref().unwrap();
        assert_eq!(p["limit"], 10);
        assert_eq!(p["sinceSeconds"], 60);
        assert_eq!(p["runId"], "run-1");
    }

    #[test]
    fn selfcheck_all_ok_passes_else_fails() {
        assert!(interpret_selfcheck(&serde_json::json!({"recordOk":true,"diagnosticOk":true,"redactionOk":true})).is_ok());
        let err = interpret_selfcheck(&serde_json::json!({"recordOk":false,"diagnosticOk":true,"redactionOk":true})).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }
}
