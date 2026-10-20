//! Claude Code session owner — one long-lived `claude --print
//! --input-format stream-json --output-format stream-json
//! --permission-prompt-tool stdio` child per AgentDeck session.
//!
//! The owner task is the only holder of the child's stdin/stdout. It
//! serializes client commands and CC output in one `select!` loop:
//!
//!   - turn start  → `{"type":"user",...}` line + `TurnStarted`
//!   - turn cancel → `control_request{subtype:"interrupt"}`; CC answers
//!     with a `result(error_during_execution)` that becomes `canceled`
//!   - approval    → `control_request{subtype:"can_use_tool"}` from CC
//!     becomes `ActionRequest`; the decision goes back as
//!     `control_response{behavior:"allow"|"deny"}`
//!   - permission mode → `control_request{subtype:"set_permission_mode"}`
//!   - close       → stdin EOF, drain stdout, reap child and process group,
//!     then report `AgentSessionExit` (RuntimeHub emits `SessionClosed`)
//!
//! Wire shapes verified against `claude` 2.1.304 (2026-10-20); see
//! `docs/plans/2026-10-20-cc-interactive-session-design.md`.

use crate::agent::{AgentEventSender, AgentSessionExit};
use crate::claude_code::translate::{ClaudeCodeTranslator, PermissionRoute};
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, AgentKind, ClaudeCodePermissionMode, ProtocolError,
    ServerEvent, SessionId, SessionOutcome, ThreadId, TurnId, TurnNextState, TurnOutcome,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin};
use tokio::sync::{mpsc, oneshot};

/// How long a closing session may take to flush stdout and exit before
/// the owner kills its process group.
const CLOSE_GRACE: Duration = Duration::from_secs(10);
const STDERR_TAIL_BYTES: usize = 4096;

pub(crate) type Reply = oneshot::Sender<Result<(), ProtocolError>>;

pub(crate) enum SessionCommand {
    StartTurn {
        turn_id: TurnId,
        prompt: String,
        reply: Reply,
    },
    CancelTurn {
        turn_id: TurnId,
        reply: Reply,
    },
    Decision {
        decision: ActionDecision,
        reply: Reply,
    },
    SetPermissionMode {
        mode: ClaudeCodePermissionMode,
        reply: Reply,
    },
    Close {
        reply: Reply,
    },
}

pub(crate) struct OwnerStart {
    pub session_id: SessionId,
    pub thread_id: ThreadId,
    pub permission_mode: ClaudeCodePermissionMode,
    pub initial_turn: Option<(TurnId, String)>,
}

/// Spawn the owner task for an already-spawned child (stdin/stdout/stderr
/// piped). Tests drive this with a fake child.
pub(crate) fn spawn_owner(
    mut child: Child,
    start: OwnerStart,
    events: AgentEventSender,
    exit: oneshot::Sender<AgentSessionExit>,
) -> Result<(mpsc::Sender<SessionCommand>, tokio::task::AbortHandle), ProtocolError> {
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(error(
            "cc-spawn-failed",
            "claude child is missing stdio pipes",
        ));
    };
    let stderr_tail = child.stderr.take().map(|mut stderr| {
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let _ = stderr.read_to_end(&mut buf).await;
            let start = buf.len().saturating_sub(STDERR_TAIL_BYTES);
            String::from_utf8_lossy(&buf[start..]).trim().to_string()
        })
    });
    let (commands_tx, commands) = mpsc::channel(16);
    let mut translator = ClaudeCodeTranslator::new(start.session_id.clone(), start.permission_mode);
    translator.set_thread_id(start.thread_id.clone());
    let owner = Owner {
        session_id: start.session_id,
        thread_id: start.thread_id,
        stdin: Some(stdin),
        translator,
        events,
        active_turn: None,
        cancel_requested: false,
        pending: HashMap::new(),
        pending_modes: HashMap::new(),
        next_control_id: 0,
    };
    let task = tokio::spawn(owner.run(
        child,
        BufReader::new(stdout),
        stderr_tail,
        commands,
        start.initial_turn,
        exit,
    ));
    Ok((commands_tx, task.abort_handle()))
}

struct Owner {
    session_id: SessionId,
    thread_id: ThreadId,
    stdin: Option<ChildStdin>,
    translator: ClaudeCodeTranslator,
    events: AgentEventSender,
    active_turn: Option<TurnId>,
    cancel_requested: bool,
    /// Open `can_use_tool` prompts keyed by control request id.
    pending: HashMap<String, PermissionRoute>,
    /// Our `set_permission_mode` requests awaiting CC's answer.
    pending_modes: HashMap<String, ClaudeCodePermissionMode>,
    next_control_id: u64,
}

impl Owner {
    async fn run(
        mut self,
        mut child: Child,
        stdout: BufReader<tokio::process::ChildStdout>,
        mut stderr_tail: Option<tokio::task::JoinHandle<String>>,
        mut commands: mpsc::Receiver<SessionCommand>,
        initial_turn: Option<(TurnId, String)>,
        exit: oneshot::Sender<AgentSessionExit>,
    ) {
        let mut lines = stdout.lines();
        let mut closing = false;
        let mut failure = self
            .send_control(json!({"subtype": "initialize"}))
            .await
            .err();
        if failure.is_none()
            && let Some((turn_id, prompt)) = initial_turn
        {
            failure = self.begin_turn(turn_id, prompt).await.err();
        }

        // Live phase: commands and CC output interleave.
        while failure.is_none() && !closing {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(SessionCommand::Close { reply }) => {
                        let _ = reply.send(Ok(()));
                        closing = true;
                    }
                    Some(command) => self.handle_command(command).await,
                    // Every sender dropped: the adapter forgot this session.
                    None => closing = true,
                },
                line = lines.next_line() => match line {
                    Ok(Some(line)) => self.handle_line(&line).await,
                    Ok(None) => failure = Some(self.exited_error(&mut child, &mut stderr_tail).await),
                    Err(e) => failure = Some(error("cc-stdout-read-failed", format!("read claude stdout: {e}"))),
                },
            }
        }

        // Shutdown phase: interrupt a running turn, close stdin and keep
        // draining stdout so CC never blocks on a full pipe while exiting.
        if closing && self.active_turn.is_some() && !self.cancel_requested {
            self.cancel_requested = true;
            let _ = self.send_control(json!({"subtype": "interrupt"})).await;
        }
        self.stdin = None;
        let drained = tokio::time::timeout(CLOSE_GRACE, async {
            loop {
                tokio::select! {
                    command = commands.recv(), if !commands.is_closed() => {
                        if let Some(command) = command {
                            reject(command, "session-closing", "session is closing");
                        }
                    }
                    line = lines.next_line() => match line {
                        Ok(Some(line)) => self.handle_line(&line).await,
                        _ => break,
                    },
                }
            }
        })
        .await
        .is_ok();
        let cleanup_confirmed = reap(&mut child, drained).await;
        if failure.is_none() && !cleanup_confirmed {
            failure = Some(error(
                "cc-cleanup-failed",
                "claude child did not exit and could not be reaped",
            ));
        }

        if let Some(turn_id) = self.active_turn.take() {
            let (outcome, turn_error) = if closing && failure.is_none() {
                (TurnOutcome::Canceled, None)
            } else {
                (TurnOutcome::Failed, failure.clone())
            };
            self.emit(self.turn_finished(turn_id, outcome, TurnNextState::Closing, turn_error))
                .await;
        }
        commands.close();
        while let Ok(command) = commands.try_recv() {
            reject(command, "session-closing", "session is closing");
        }
        let _ = exit.send(AgentSessionExit {
            thread_id: Some(self.thread_id.clone()),
            outcome: if failure.is_some() {
                SessionOutcome::Failed
            } else {
                SessionOutcome::Closed
            },
            error: failure,
            cleanup_confirmed,
        });
    }

    async fn handle_command(&mut self, command: SessionCommand) {
        match command {
            SessionCommand::StartTurn {
                turn_id,
                prompt,
                reply,
            } => {
                let _ = reply.send(self.begin_turn(turn_id, prompt).await);
            }
            SessionCommand::CancelTurn { turn_id, reply } => {
                let result = if self.active_turn.as_ref() != Some(&turn_id) {
                    Err(error(
                        "turn-not-active",
                        format!("turn {} is not running", turn_id.0),
                    ))
                } else if self.cancel_requested {
                    Ok(())
                } else {
                    self.cancel_requested = true;
                    self.send_control(json!({"subtype": "interrupt"}))
                        .await
                        .map(drop)
                };
                let _ = reply.send(result);
            }
            SessionCommand::Decision { decision, reply } => {
                let _ = reply.send(self.answer_permission(decision).await);
            }
            SessionCommand::SetPermissionMode { mode, reply } => {
                let result = self
                    .send_control(json!({
                        "subtype": "set_permission_mode",
                        "mode": super::adapter::permission_mode_to_cli(mode),
                    }))
                    .await
                    .map(|request_id| {
                        self.pending_modes.insert(request_id, mode);
                    });
                let _ = reply.send(result);
            }
            SessionCommand::Close { .. } => unreachable!("close is handled by the run loop"),
        }
    }

    async fn begin_turn(&mut self, turn_id: TurnId, prompt: String) -> Result<(), ProtocolError> {
        if let Some(active) = &self.active_turn {
            return Err(error(
                "turn-already-running",
                format!("turn {} is still running", active.0),
            ));
        }
        self.write_line(&json!({
            "type": "user",
            "message": {"role": "user", "content": prompt},
        }))
        .await?;
        self.translator.set_turn_id(turn_id.clone());
        self.active_turn = Some(turn_id.clone());
        self.cancel_requested = false;
        self.emit(ServerEvent::TurnStarted {
            session_id: self.session_id.clone(),
            thread_id: self.thread_id.clone(),
            agent_kind: AgentKind::ClaudeCode,
            turn_id,
        })
        .await;
        Ok(())
    }

    async fn answer_permission(&mut self, decision: ActionDecision) -> Result<(), ProtocolError> {
        let Some(route) = self.pending.remove(&decision.request_id) else {
            return Err(error(
                "cc-decision-no-route",
                format!("no pending permission for request {}", decision.request_id),
            ));
        };
        let response = match decision.decision {
            ActionDecisionKind::Approve => {
                let mut input = route.input;
                // AskUserQuestion reads the user's picks from updatedInput.answers.
                if let (Some(answers), Some(object)) = (decision.answers, input.as_object_mut()) {
                    object.insert("answers".into(), json!(answers));
                }
                let mut allow = json!({"behavior": "allow", "updatedInput": input});
                if decision.persist && route.suggestions.as_array().is_some_and(|s| !s.is_empty()) {
                    allow["updatedPermissions"] = route.suggestions;
                }
                allow
            }
            ActionDecisionKind::Deny => {
                let message = decision
                    .message
                    .filter(|message| !message.trim().is_empty())
                    .unwrap_or_else(|| "Denied by the user in AgentDeck".into());
                json!({"behavior": "deny", "message": message})
            }
        };
        self.write_line(&json!({
            "type": "control_response",
            "response": {
                "subtype": "success",
                "request_id": route.request_id,
                "response": response,
            },
        }))
        .await
    }

    async fn handle_line(&mut self, line: &str) {
        let out = self.translator.translate_line(line);
        let parsed = serde_json::from_str::<Value>(line).unwrap_or(Value::Null);
        let request_id = parsed.get("request_id").and_then(Value::as_str);
        match parsed.get("type").and_then(Value::as_str) {
            _ if out.permission_route_hint.is_some() => {
                let route = out.permission_route_hint.expect("checked above");
                self.pending.insert(route.request_id.clone(), route);
            }
            Some("control_cancel_request") => {
                if let Some(request_id) = request_id {
                    self.pending.remove(request_id);
                }
            }
            Some("control_response") => self.handle_control_response(&parsed["response"]).await,
            Some("control_request") => {
                // We register no hooks or SDK MCP servers, so any other
                // inbound control request is unexpected; answer so CC never
                // waits on us forever.
                let _ = self
                    .write_line(&json!({
                        "type": "control_response",
                        "response": {
                            "subtype": "error",
                            "request_id": request_id,
                            "error": "unsupported control request",
                        },
                    }))
                    .await;
            }
            _ => {}
        }
        for mut event in out.events {
            if let ServerEvent::TurnFinished {
                outcome,
                error: turn_error,
                ..
            } = &mut event
            {
                // A result without a running turn has no caller to report to.
                if self.active_turn.take().is_none() {
                    continue;
                }
                if self.cancel_requested {
                    *outcome = TurnOutcome::Canceled;
                    *turn_error = None;
                }
                self.cancel_requested = false;
                self.pending.clear();
            }
            self.emit(event).await;
        }
    }

    /// Write one control request; returns its id so the caller can match
    /// CC's `control_response`.
    async fn send_control(&mut self, request: Value) -> Result<String, ProtocolError> {
        self.next_control_id += 1;
        let request_id = format!("agentdeck-{}", self.next_control_id);
        self.write_line(&json!({
            "type": "control_request",
            "request_id": request_id,
            "request": request,
        }))
        .await?;
        Ok(request_id)
    }

    /// CC answers `set_permission_mode` asynchronously. The client command was
    /// already acknowledged (RuntimeHub handles it inline), so the outcome is
    /// published as an event: the mode change, or a session error.
    async fn handle_control_response(&mut self, response: &Value) {
        let Some(mode) = response
            .get("request_id")
            .and_then(Value::as_str)
            .and_then(|id| self.pending_modes.remove(id))
        else {
            return;
        };
        if response.get("subtype").and_then(Value::as_str) == Some("success") {
            if let Some(event) = self.translator.observe_permission_mode(mode) {
                self.emit(event).await;
            }
            return;
        }
        let reason = response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("claude rejected the permission mode");
        self.emit(ServerEvent::Error {
            session_id: Some(self.session_id.clone()),
            error: error("cc-permission-mode-rejected", reason),
        })
        .await;
    }

    async fn write_line(&mut self, value: &Value) -> Result<(), ProtocolError> {
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(error("session-closing", "claude stdin is already closed"));
        };
        let mut line = value.to_string();
        line.push('\n');
        let write = async {
            stdin.write_all(line.as_bytes()).await?;
            stdin.flush().await
        };
        write
            .await
            .map_err(|e| error("cc-stdin-write-failed", format!("write claude stdin: {e}")))
    }

    async fn emit(&self, event: ServerEvent) {
        let _ = self.events.send(event).await;
    }

    fn turn_finished(
        &self,
        turn_id: TurnId,
        outcome: TurnOutcome,
        next_state: TurnNextState,
        error: Option<ProtocolError>,
    ) -> ServerEvent {
        ServerEvent::TurnFinished {
            session_id: self.session_id.clone(),
            thread_id: self.thread_id.clone(),
            agent_kind: AgentKind::ClaudeCode,
            turn_id,
            outcome,
            next_state,
            summary: None,
            error,
        }
    }

    async fn exited_error(
        &self,
        child: &mut Child,
        stderr_tail: &mut Option<tokio::task::JoinHandle<String>>,
    ) -> ProtocolError {
        let status = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        let mut message = match status {
            Ok(Ok(status)) => format!("claude exited unexpectedly ({status})"),
            _ => "claude closed stdout unexpectedly".to_string(),
        };
        if let Some(tail) = stderr_tail.take()
            && let Ok(Ok(tail)) = tokio::time::timeout(Duration::from_secs(1), tail).await
            && !tail.is_empty()
        {
            message.push_str(": ");
            message.push_str(&tail);
        }
        error("cc-process-exited", message)
    }
}

/// Wait for the child (killing its process group if it would not exit in
/// time) and sweep any orphans left in the group. True once reaped.
async fn reap(child: &mut Child, exited_gracefully: bool) -> bool {
    let pid = child.id();
    if !exited_gracefully
        || tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .is_err()
    {
        if let Some(pid) = pid {
            kill_group(pid);
        }
        let _ = child.start_kill();
    }
    let reaped = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .is_ok_and(|status| status.is_ok());
    if let Some(pid) = pid {
        // Tool subprocesses (e.g. a backgrounded Bash) may outlive claude.
        kill_group(pid);
    }
    reaped
}

fn reject(command: SessionCommand, code: &str, message: &str) {
    let reply = match command {
        SessionCommand::StartTurn { reply, .. }
        | SessionCommand::CancelTurn { reply, .. }
        | SessionCommand::Decision { reply, .. }
        | SessionCommand::SetPermissionMode { reply, .. }
        | SessionCommand::Close { reply } => reply,
    };
    let _ = reply.send(Err(error(code, message)));
}

fn error(code: &str, message: impl Into<String>) -> ProtocolError {
    ProtocolError {
        code: code.into(),
        message: message.into(),
        diagnostic_ref: None,
    }
}

pub(crate) fn kill_group(pid: u32) {
    #[cfg(unix)]
    unsafe {
        libc_kill(-(pid as i32), SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = pid;
}

#[cfg(unix)]
const SIGKILL: i32 = 9;
#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentdeck_protocol::{AgentItem, AgentItemState};
    use std::process::Stdio;

    /// Fake `claude` speaking the stream-json control protocol shapes
    /// recorded from claude 2.1.304.
    const FAKE_CLAUDE: &str = r#"
while IFS= read -r line; do
  case "$line" in
    *'"subtype":"initialize"'*) echo '{"type":"control_response","response":{"subtype":"success","request_id":"agentdeck-1","response":{}}}' ;;
    *'"subtype":"set_permission_mode"'*)
      id=$(printf %s "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p')
      case "$line" in
        *bypassPermissions*) echo "{\"type\":\"control_response\",\"response\":{\"subtype\":\"error\",\"request_id\":\"$id\",\"error\":\"not launched with bypass\"}}" ;;
        *) echo "{\"type\":\"control_response\",\"response\":{\"subtype\":\"success\",\"request_id\":\"$id\",\"response\":{}}}" ;;
      esac ;;
    *'"subtype":"interrupt"'*) echo '{"type":"result","subtype":"error_during_execution","is_error":true,"session_id":"thread-x"}' ;;
    *'"answers":{"color":"blue"}'*) echo '{"type":"assistant","session_id":"thread-x","message":{"id":"m3","content":[{"type":"text","text":"got blue"}]}}'
      echo '{"type":"result","subtype":"success","is_error":false,"session_id":"thread-x"}' ;;
    *ask-me*) echo '{"type":"control_request","request_id":"ask-1","request":{"subtype":"can_use_tool","tool_name":"AskUserQuestion","input":{"questions":[{"question":"color","options":[{"label":"blue"}]}]}}}' ;;
    *'"behavior":"allow"'*) echo '{"type":"assistant","session_id":"thread-x","message":{"id":"m2","content":[{"type":"text","text":"approved"}]}}'
      echo '{"type":"result","subtype":"success","is_error":false,"session_id":"thread-x"}' ;;
    *approve*) echo '{"type":"control_request","request_id":"perm-1","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"ls"},"permission_suggestions":[]}}' ;;
    *slow*) ;;
    *'"type":"user"'*) echo '{"type":"assistant","session_id":"thread-x","message":{"id":"m1","content":[{"type":"text","text":"hi"}]}}'
      echo '{"type":"result","subtype":"success","is_error":false,"session_id":"thread-x"}' ;;
  esac
done
"#;

    async fn next(events: &mut mpsc::Receiver<ServerEvent>) -> ServerEvent {
        tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("event within 5s")
            .expect("events channel open")
    }

    async fn call(
        commands: &mpsc::Sender<SessionCommand>,
        command: impl FnOnce(Reply) -> SessionCommand,
    ) -> Result<(), ProtocolError> {
        let (reply, answer) = oneshot::channel();
        commands.send(command(reply)).await.expect("owner alive");
        answer.await.expect("owner replies")
    }

    fn turn(id: &str) -> TurnId {
        TurnId(id.into())
    }

    #[tokio::test]
    async fn one_child_serves_turns_approvals_cancel_and_close() {
        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", FAKE_CLAUDE])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let child = command.spawn().expect("spawn fake claude");
        let (events_tx, mut events) = mpsc::channel(64);
        let (exit_tx, exit_rx) = oneshot::channel();
        let (commands, _abort) = spawn_owner(
            child,
            OwnerStart {
                session_id: SessionId("s".into()),
                thread_id: ThreadId("thread-x".into()),
                permission_mode: ClaudeCodePermissionMode::Default,
                initial_turn: Some((turn("t1"), "hello".into())),
            },
            events_tx,
            exit_tx,
        )
        .expect("owner starts");

        // Turn 1 comes from the initial prompt.
        assert!(
            matches!(next(&mut events).await, ServerEvent::TurnStarted { turn_id, .. } if turn_id == turn("t1"))
        );
        assert!(
            matches!(next(&mut events).await, ServerEvent::AgentItem { item: AgentItem::AssistantMessage { text, .. }, state: AgentItemState::Completed, .. } if text == "hi")
        );
        assert!(
            matches!(next(&mut events).await, ServerEvent::TurnFinished { turn_id, outcome: TurnOutcome::Succeeded, next_state: TurnNextState::Ready, .. } if turn_id == turn("t1"))
        );

        // Turn 2 on the same child asks for approval.
        call(&commands, |reply| SessionCommand::StartTurn {
            turn_id: turn("t2"),
            prompt: "approve".into(),
            reply,
        })
        .await
        .expect("second turn accepted");
        assert!(
            matches!(next(&mut events).await, ServerEvent::TurnStarted { turn_id, .. } if turn_id == turn("t2"))
        );
        let ServerEvent::ActionRequest { request, .. } = next(&mut events).await else {
            panic!("expected ActionRequest");
        };
        assert_eq!(request.request_id, "perm-1");
        let unknown = ActionDecision {
            request_id: "nope".into(),
            decision: ActionDecisionKind::Approve,
            persist: false,
            message: None,
            answers: None,
        };
        assert_eq!(
            call(&commands, |reply| SessionCommand::Decision {
                decision: unknown,
                reply
            })
            .await
            .unwrap_err()
            .code,
            "cc-decision-no-route"
        );
        let approve = ActionDecision {
            request_id: "perm-1".into(),
            decision: ActionDecisionKind::Approve,
            persist: false,
            message: None,
            answers: None,
        };
        call(&commands, |reply| SessionCommand::Decision {
            decision: approve,
            reply,
        })
        .await
        .expect("decision routed");
        assert!(
            matches!(next(&mut events).await, ServerEvent::AgentItem { item: AgentItem::AssistantMessage { text, .. }, .. } if text == "approved")
        );
        assert!(
            matches!(next(&mut events).await, ServerEvent::TurnFinished { turn_id, outcome: TurnOutcome::Succeeded, .. } if turn_id == turn("t2"))
        );

        // Turn 3 runs until interrupted; a concurrent turn is refused.
        call(&commands, |reply| SessionCommand::StartTurn {
            turn_id: turn("t3"),
            prompt: "slow".into(),
            reply,
        })
        .await
        .expect("third turn accepted");
        assert!(
            matches!(next(&mut events).await, ServerEvent::TurnStarted { turn_id, .. } if turn_id == turn("t3"))
        );
        assert_eq!(
            call(&commands, |reply| SessionCommand::StartTurn {
                turn_id: turn("t4"),
                prompt: "x".into(),
                reply
            })
            .await
            .unwrap_err()
            .code,
            "turn-already-running"
        );
        call(&commands, |reply| SessionCommand::CancelTurn {
            turn_id: turn("t3"),
            reply,
        })
        .await
        .expect("interrupt sent");
        assert!(
            matches!(next(&mut events).await, ServerEvent::TurnFinished { turn_id, outcome: TurnOutcome::Canceled, next_state: TurnNextState::Ready, error: None, .. } if turn_id == turn("t3"))
        );

        call(&commands, |reply| SessionCommand::Close { reply })
            .await
            .expect("close accepted");
        let exit = tokio::time::timeout(Duration::from_secs(15), exit_rx)
            .await
            .expect("owner exits")
            .expect("exit reported");
        assert!(matches!(exit.outcome, SessionOutcome::Closed));
        assert!(exit.error.is_none());
        assert!(exit.cleanup_confirmed);
        assert_eq!(exit.thread_id, Some(ThreadId("thread-x".into())));
    }

    #[tokio::test]
    async fn permission_mode_changes_follow_claude_answers() {
        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", FAKE_CLAUDE])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let (events_tx, mut events) = mpsc::channel(64);
        let (exit_tx, _exit_rx) = oneshot::channel();
        let (commands, _abort) = spawn_owner(
            command.spawn().expect("spawn fake claude"),
            OwnerStart {
                session_id: SessionId("s".into()),
                thread_id: ThreadId("thread-x".into()),
                permission_mode: ClaudeCodePermissionMode::Default,
                initial_turn: None,
            },
            events_tx,
            exit_tx,
        )
        .expect("owner starts");

        for mode in [
            ClaudeCodePermissionMode::Plan,
            ClaudeCodePermissionMode::BypassPermissions,
        ] {
            call(&commands, |reply| SessionCommand::SetPermissionMode {
                mode,
                reply,
            })
            .await
            .expect("request written");
        }
        assert!(matches!(
            next(&mut events).await,
            ServerEvent::VendorPanelEvent {
                payload: agentdeck_protocol::VendorPanelPayload::ClaudeCode(
                    agentdeck_protocol::ClaudeCodeVendorPanelEvent::PermissionModeChanged {
                        mode: ClaudeCodePermissionMode::Plan
                    }
                ),
                ..
            }
        ));
        assert!(matches!(
            next(&mut events).await,
            ServerEvent::Error { error, .. } if error.code == "cc-permission-mode-rejected"
        ));
    }

    #[tokio::test]
    async fn answers_ride_in_updated_input() {
        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", FAKE_CLAUDE])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let (events_tx, mut events) = mpsc::channel(64);
        let (exit_tx, _exit_rx) = oneshot::channel();
        let (commands, _abort) = spawn_owner(
            command.spawn().expect("spawn fake claude"),
            OwnerStart {
                session_id: SessionId("s".into()),
                thread_id: ThreadId("thread-x".into()),
                permission_mode: ClaudeCodePermissionMode::Default,
                initial_turn: Some((turn("t1"), "ask-me".into())),
            },
            events_tx,
            exit_tx,
        )
        .expect("owner starts");
        assert!(matches!(
            next(&mut events).await,
            ServerEvent::TurnStarted { .. }
        ));
        assert!(matches!(
            next(&mut events).await,
            ServerEvent::ActionRequest { .. }
        ));
        let answer = ActionDecision {
            request_id: "ask-1".into(),
            decision: ActionDecisionKind::Approve,
            persist: false,
            message: None,
            answers: Some([("color".to_string(), "blue".to_string())].into()),
        };
        call(&commands, |reply| SessionCommand::Decision {
            decision: answer,
            reply,
        })
        .await
        .expect("answer routed");
        assert!(matches!(
            next(&mut events).await,
            ServerEvent::AgentItem { item: AgentItem::AssistantMessage { text, .. }, .. } if text == "got blue"
        ));
    }

    #[tokio::test]
    async fn unexpected_child_exit_fails_the_running_turn_and_session() {
        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "read -r _; read -r _; echo boom >&2; exit 3"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let (events_tx, mut events) = mpsc::channel(64);
        let (exit_tx, exit_rx) = oneshot::channel();
        let _owner = spawn_owner(
            command.spawn().expect("spawn"),
            OwnerStart {
                session_id: SessionId("s".into()),
                thread_id: ThreadId("thread-x".into()),
                permission_mode: ClaudeCodePermissionMode::Default,
                initial_turn: Some((turn("t1"), "hello".into())),
            },
            events_tx,
            exit_tx,
        )
        .expect("owner starts");
        assert!(matches!(
            next(&mut events).await,
            ServerEvent::TurnStarted { .. }
        ));
        let ServerEvent::TurnFinished {
            outcome: TurnOutcome::Failed,
            next_state: TurnNextState::Closing,
            error: Some(error),
            ..
        } = next(&mut events).await
        else {
            panic!("expected failed closing turn");
        };
        assert_eq!(error.code, "cc-process-exited");
        assert!(
            error.message.contains("boom"),
            "stderr tail in {}",
            error.message
        );
        let exit = tokio::time::timeout(Duration::from_secs(15), exit_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(exit.outcome, SessionOutcome::Failed));
        assert!(exit.cleanup_confirmed);
    }
}
