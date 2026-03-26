use anyhow::Result;
use clap::CommandFactory;
use clap_complete::generate;

use crate::cli::{Cli, CompletionsArgs};

/// Generate shell completion output for the requested shell.
///
/// # Errors
///
/// This function currently does not return runtime errors.
pub fn run(args: CompletionsArgs) -> Result<()> {
    let mut cmd = Cli::command();
    generate(args.shell, &mut cmd, "a8c-secrets", &mut std::io::stdout());
    Ok(())
}
