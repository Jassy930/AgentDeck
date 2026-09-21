use super::*;
use agentdeck_protocol::{
    AgentKind, ClientCommand, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode,
    CodexSessionOptions, InitialTurn, SessionId, SessionStart, TurnId, VendorSessionOptions,
};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc;

pub struct LiveCli {
    child: std::process::Child,
    input: Option<std::process::ChildStdin>,
    output: mpsc::Receiver<Value>,
    stderr: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
    deadline: Instant,
    pub events: Vec<Value>,
}

impl LiveCli {
    pub fn spawn(command: Command, timeout: Duration) -> Self {
        Self::spawn_with_output_limit(command, timeout, usize::MAX)
    }

    pub fn spawn_with_output_limit(mut command: Command, timeout: Duration, lines: usize) -> Self {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let stderr = Some(drain_thread(child.stderr.take().unwrap()));
        let (tx, output) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().take(lines) {
                let value =
                    serde_json::from_str(&line.unwrap()).expect("CLI must emit valid JSONL");
                if tx.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            output,
            stderr,
            deadline: Instant::now() + timeout,
            events: vec![],
        }
    }

    pub fn send(&mut self, command: ClientCommand) {
        self.send_raw(&serde_json::to_string(&command).unwrap());
    }

    pub fn send_raw(&mut self, line: &str) {
        let input = self.input.as_mut().expect("stdin still open");
        writeln!(input, "{line}").unwrap();
        input.flush().unwrap();
    }

    pub fn next(&mut self) -> Value {
        let event = self
            .output
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|error| {
                panic!(
                    "live CLI stopped or timed out: {error}; events={:?}",
                    self.events
                )
            });
        self.events.push(event.clone());
        event
    }

    pub fn finish(&mut self) -> ExitStatus {
        self.input.take();
        while let Ok(event) = self
            .output
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
        {
            self.events.push(event);
        }
        loop {
            if let Some(status) = self.child.try_wait().unwrap()
                && self.stderr.as_ref().unwrap().is_finished()
            {
                let stderr = finish_drain("stderr", self.stderr.take().unwrap()).unwrap();
                assert!(
                    Instant::now() < self.deadline,
                    "live CLI exceeded timeout: {}",
                    String::from_utf8_lossy(&stderr)
                );
                return status;
            }
            assert!(Instant::now() < self.deadline, "live CLI did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for LiveCli {
    fn drop(&mut self) {
        if self.stderr.is_some() {
            kill_owned_process_tree(self.child.id() as i32, &mut self.child);
            let _ = self.child.wait();
        }
    }
}

pub fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "agentdeck-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

pub fn session_start(cwd: &Path) -> ClientCommand {
    ClientCommand::SessionStart(SessionStart {
        session_id: SessionId("cli-live-m0".into()),
        agent_kind: AgentKind::Codex,
        cwd: cwd.to_owned(),
        resume_thread_id: None,
        initial_turn: Some(InitialTurn {
            turn_id: TurnId("turn-1".into()),
            prompt: "Write three short sentences about trees. Do not use tools.".into(),
        }),
        vendor_options: VendorSessionOptions::Codex(CodexSessionOptions {
            approval_policy: CodexApprovalPolicy::Never,
            sandbox: CodexSandboxMode::ReadOnly,
            persist_approval: false,
            reasoning_effort: CodexReasoningEffort::Medium,
            mcp_overrides: vec![],
        }),
        runtime_options: Default::default(),
    })
}

pub fn four_turn_scenario(command: Command, root: &Path, timeout: Duration) {
    let mut cli = LiveCli::spawn(command, timeout);
    cli.send(session_start(root));
    let started = cli.next();
    assert_eq!(started["type"], "sessionStarted", "{started}");
    let thread_id = started["threadId"].as_str().unwrap().to_owned();
    assert!(!thread_id.is_empty());
    assert_eq!(cli.next()["type"], "sessionCapabilities");
    for turn in 1..=4 {
        let turn_id = format!("turn-{turn}");
        if turn > 1 {
            cli.send(ClientCommand::TurnStart {
                session_id: SessionId("cli-live-m0".into()), turn_id: TurnId(turn_id.clone()),
                prompt: if turn == 3 { "Write a long numbered list of 200 facts about trees, one sentence each. Start immediately. Do not use tools." }
                    else { "Write three short sentences about the ocean. Do not use tools." }.into(),
            });
        }
        let event = cli.next();
        assert_eq!(event["type"], "turnStarted", "{event}");
        assert_eq!(event["turnId"], turn_id);
        let mut messages: HashMap<String, (String, bool)> = HashMap::new();
        let mut streamed = false;
        let mut pinged = false;
        loop {
            let event = cli.next();
            if event["reply"] == "ping" {
                assert_eq!(event["ok"], true);
                pinged = true;
                continue;
            }
            assert_eq!(event["sessionId"], "cli-live-m0", "{event}");
            assert_eq!(event["threadId"], thread_id, "{event}");
            assert_eq!(event["agentKind"], "codex", "{event}");
            assert_eq!(event["turnId"], turn_id, "{event}");
            match event["type"].as_str().unwrap() {
                "agentItem" => {
                    if event["item"]["kind"] != "assistantMessage" {
                        continue;
                    }
                    let id = event["itemId"].as_str().unwrap();
                    assert!(!id.is_empty());
                    let text = event["item"]["text"].as_str().unwrap();
                    let previous = messages.entry(id.into()).or_default();
                    assert!(
                        !previous.1,
                        "duplicate completed or post-completion item: {event}"
                    );
                    assert!(
                        text.starts_with(&previous.0),
                        "non-cumulative snapshot: {event}"
                    );
                    previous.0 = text.into();
                    previous.1 = event["state"] == "completed";
                    if event["state"] == "streaming" && !streamed {
                        streamed = true;
                        if turn == 3 {
                            cli.send(ClientCommand::Ping);
                            cli.send(ClientCommand::TurnCancel {
                                session_id: SessionId("cli-live-m0".into()),
                                turn_id: TurnId(turn_id.clone()),
                            });
                        }
                    }
                }
                "turnFinished" => {
                    assert!(streamed, "a completed-only turn is not streaming");
                    assert_eq!(
                        event["outcome"],
                        if turn == 3 { "canceled" } else { "succeeded" }
                    );
                    assert_eq!(event["nextState"], "ready");
                    if turn != 3 {
                        assert!(messages.values().all(|(_, completed)| *completed));
                    }
                    break;
                }
                _ => panic!("unexpected turn event: {event}"),
            }
        }
        if turn == 3 && !pinged {
            let ping = cli.next();
            assert_eq!(
                ping["reply"], "ping",
                "Ping must remain responsive during cancel"
            );
            assert_eq!(ping["ok"], true);
        }
    }
    cli.send(ClientCommand::SessionClose {
        session_id: SessionId("cli-live-m0".into()),
    });
    let closed = cli.next();
    assert_eq!(closed["type"], "sessionClosed");
    assert_eq!(closed["outcome"], "closed");
    assert!(cli.finish().success(), "live CLI failed: {:?}", cli.events);
    assert_eq!(
        cli.events
            .iter()
            .filter(|v| v["type"] == "turnFinished")
            .count(),
        4
    );
    assert_eq!(
        cli.events
            .iter()
            .filter(|v| v["type"] == "sessionClosed")
            .count(),
        1
    );
    assert_eq!(cli.events.last().unwrap()["type"], "sessionClosed");
    verify_evidence(root, &cli.events);
}

fn jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn verify_evidence(root: &Path, events: &[Value]) {
    let records: Vec<_> = std::fs::read_dir(root.join("runs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(records.len(), 1, "all turns belong to one run record");
    let record = jsonl(&records[0]);
    assert_eq!(record.first().unwrap()["kind"], "runHeader");
    assert_eq!(record.last().unwrap()["kind"], "runFooter");
    let recorded: Vec<_> = record.iter().filter(|v| v.get("type").is_some()).collect();
    let emitted: Vec<_> = events.iter().filter(|v| v.get("type").is_some()).collect();
    assert_eq!(
        recorded, emitted,
        "run record must preserve exact IPC event order"
    );
    let diagnostics = jsonl(&root.join("diagnostic.log"));
    let details = |name: &str| -> Vec<Value> {
        diagnostics
            .iter()
            .filter(|v| v["runId"] == "cli-live-m0" && v["event"] == name)
            .map(|v| serde_json::from_str(v["detail"].as_str().unwrap()).unwrap())
            .collect()
    };
    let spawned = details("codex_child_spawned");
    assert_eq!(spawned.len(), 1);
    let pid = spawned[0]["childPid"].as_i64().unwrap() as i32;
    let turns = details("codex_turn_started");
    assert_eq!(turns.len(), 4);
    for (index, turn) in turns.iter().enumerate() {
        assert_eq!(turn["childPid"], pid);
        assert_eq!(turn["turnId"], format!("turn-{}", index + 1));
    }
    let cleanup = details("codex_cleanup_completed");
    assert_eq!(cleanup.len(), 1);
    assert_eq!(cleanup[0]["childPid"], pid);
    assert_eq!(cleanup[0]["childWaited"], true);
    assert_eq!(cleanup[0]["processGroupGone"], true);
    #[cfg(unix)]
    for target in [pid, -pid] {
        assert_eq!(
            unsafe { libc::kill(target, 0) },
            -1,
            "child or its process group survived close"
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }
    eprintln!(
        "M0 CLI verified: four turns, one child PID {pid}, clean close; evidence={}",
        root.display()
    );
}
