//! Output adapters for terminal tables, JSON/CSV exports, and the live TUI.
//!
//! Output policy, such as MAC masking, is applied here rather than in the scan
//! model. That keeps cache/history/identity rules on raw evidence while letting
//! users redact sensitive identifiers at the boundary where data leaves the
//! process.

mod export;
mod live;
mod privacy;
mod sources;

pub use export::{to_csv, to_json, to_table};
#[allow(unused_imports)]
pub use live::run_live_table_with_time_source;
pub use live::{LiveInterfacePanel, LiveOutcome, run_live_table};
pub use privacy::{MacAddressDisplay, OutputOptions};
