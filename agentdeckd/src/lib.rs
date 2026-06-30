//! Daemon library facade — exposes modules to integration tests without
//! requiring the bin to compile. The bin (main.rs) is rebuilt in Phase 2/3
//! to consume this lib; until then bin and lib coexist as separate targets.

pub mod agent;
