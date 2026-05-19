# AgentDeck North Star

AgentDeck is a native macOS workbench and control console for local coding
agents.

It uses the official Codex app-server as the first-class protocol. The
agent-neutral boundary lives in the IPC protocol itself: the daemon
translates Codex items into a neutral `AgentItem`, and the Swift app never
knows Codex exists.

AgentDeck does not replace Codex Desktop.
AgentDeck does not try to be an IDE.
AgentDeck does not try to be a generic multi-agent chat app.

Codex writes code.
AgentDeck organizes the work.

The core of v0.1 is two beats:

1. A native streaming session — you watch the agent reason, run commands,
   and edit files in real time, and you approve or deny risky actions. This
   is the only user-perceivable "wow" in v0.1.

2. An agent-neutral adapter boundary — official products structurally cannot
   be agent-neutral, because every vendor wants to lock you to its own agent.
   A contributable neutral architecture is the durable differentiator. v0.1
   ships only a CodexAdapter, but the boundary is drawn so the community can
   add Claude Code / SSH / cloud adapters without touching the Swift app.

Its goal is to make agent work visible, controllable, and trustworthy — and
to never silently lie about what happened.
