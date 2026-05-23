//! Library entry point for the `fing` binary.
//!
//! Only the CLI module is public. The scanner, probes, model, and output modules
//! are internal implementation boundaries that can be refactored without
//! promising a library API.

pub mod cli;
mod dhcp;
mod discovery;
mod enrich;
mod identity_rules;
mod model;
mod net;
mod output;
mod probes;
mod scanner;
mod store;
mod version;
