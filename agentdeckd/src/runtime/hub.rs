//! RuntimeHub — stdin main loop, stdout writer, per-session lock,
//! worker pool. Extracted from main.rs in T2.3; AgentRouter wiring
//! added in T2.4; CodexAdapter migration to v2 in Phase 3.
//!
//! NOTE: This file moved verbatim from main.rs. References to v1
//! protocol types (IpcMessage, AgentItemKind, etc.) will not compile
//! until Phase 3 migrates them. The [[bin]] target has
//! required-features = ["daemon-bin"] so cargo skips bin compile
//! by default.

use std::sync::mpsc::{Receiver, Sender};

use crate::ipc::{ActionDecision, IpcMessage};

#[derive(Debug)]
pub(crate) enum RuntimeHubDispatch {
    StartTurn,
    StartHistory,
    Reply(IpcMessage),
}

#[derive(Debug)]
pub(crate) enum RuntimeHubWorkerDone {
    Turn(String),
    History,
}

#[derive(Debug)]
pub struct RuntimeHub {
    running_sessions: std::collections::HashSet<String>,
    decision_senders: std::collections::HashMap<String, Sender<ActionDecision>>,
    active_history_workers: usize,
    max_history_workers: usize,
}

impl RuntimeHub {
    pub fn new(max_history_workers: usize) -> Self {
        Self {
            running_sessions: std::collections::HashSet::new(),
            decision_senders: std::collections::HashMap::new(),
            active_history_workers: 0,
            max_history_workers: max_history_workers.max(1),
        }
    }

    pub(crate) fn drain_finished(&mut self, done_rx: &Receiver<RuntimeHubWorkerDone>) {
        while let Ok(done) = done_rx.try_recv() {
            match done {
                RuntimeHubWorkerDone::Turn(session_id) => self.finish_turn(&session_id),
                RuntimeHubWorkerDone::History => self.finish_history(),
            }
        }
    }

    pub(crate) fn handle_spawn_turn(
        &mut self,
        id: Option<u64>,
        session_id: &str,
        decision_tx: Sender<ActionDecision>,
    ) -> RuntimeHubDispatch {
        if self.running_sessions.contains(session_id) {
            return RuntimeHubDispatch::Reply(IpcMessage::error(
                id,
                "runtime busy: turn already running for this session",
            ));
        }
        self.running_sessions.insert(session_id.to_string());
        self.decision_senders
            .insert(session_id.to_string(), decision_tx);
        RuntimeHubDispatch::StartTurn
    }

    pub(crate) fn finish_turn(&mut self, session_id: &str) {
        self.running_sessions.remove(session_id);
        self.decision_senders.remove(session_id);
    }

    pub(crate) fn handle_action_decision(
        &self,
        id: Option<u64>,
        session_id: &str,
        decision: ActionDecision,
    ) -> RuntimeHubDispatch {
        match self.decision_senders.get(session_id) {
            Some(tx) => match tx.send(decision) {
                Ok(()) => RuntimeHubDispatch::Reply(IpcMessage::pong(id)),
                Err(_) => RuntimeHubDispatch::Reply(IpcMessage::error(
                    id,
                    "runtime approval channel closed",
                )),
            },
            None => RuntimeHubDispatch::Reply(IpcMessage::error(
                id,
                "runtime has no pending turn for action decision",
            )),
        }
    }

    pub(crate) fn handle_history_request(&mut self, id: Option<u64>) -> RuntimeHubDispatch {
        if self.active_history_workers >= self.max_history_workers {
            return RuntimeHubDispatch::Reply(IpcMessage::error(
                id,
                "history busy: too many concurrent history requests",
            ));
        }
        self.active_history_workers += 1;
        RuntimeHubDispatch::StartHistory
    }

    pub(crate) fn finish_history(&mut self) {
        self.active_history_workers = self.active_history_workers.saturating_sub(1);
    }
}
