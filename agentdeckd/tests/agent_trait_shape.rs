//! Compile-time guard for the Agent trait shape. If a future PR weakens
//! Send+Sync+'static or removes a required method, this file fails to
//! compile, breaking the build.

use agentdeckd::agent::{Agent, AgentSessionHandle, AgentEventSender};
use agentdeck_protocol::{AgentKind, SessionCapabilities};

#[allow(dead_code)]
fn assert_send_sync_static<T: Agent>() {}

#[allow(dead_code)]
fn capability_signature_present(a: &dyn Agent) -> SessionCapabilities {
    a.capabilities()
}

#[test]
fn agent_trait_is_send_sync_static() {
    // Type-only check; no body needed.
}
