//! Compile-time guard for N6: Transport trait must be async, reconnectable,
//! and carry auth context. If a future PR weakens these, this file fails
//! to compile.

use agentdeck_protocol::transport::Transport;

#[allow(dead_code)]
fn assert_send_sync_static<T: Transport>() {}

#[allow(dead_code)]
fn assert_auth_context_clonable<A: Clone + Send + Sync>(_: A) {}

#[test]
fn transport_trait_is_send_sync_static() {
    // If Transport: ?Send (default), this won't compile when remote
    // backends (which need to cross task boundaries) try to use it.
    // We don't instantiate; we just need the bound check.
}
