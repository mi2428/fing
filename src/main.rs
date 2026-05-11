//! Binary entry point.
//!
//! Runtime setup lives here; all command behavior stays in `cli` for testability.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fing::cli::run().await
}
