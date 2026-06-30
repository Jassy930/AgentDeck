//! `claude auth status` probe + auth state types.
//!
//! Populated in Task 4B. Per K9 / N8, AgentDeck never reads, stores, or
//! forwards Claude credentials — this module will only shell out to
//! `claude auth status` (exit code + JSON) and surface a tristate
//! authenticated / unauthenticated / unknown to capabilities.
