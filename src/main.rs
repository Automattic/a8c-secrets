mod cli;
mod commands;
mod config;
mod crypto;
mod manual;
mod permissions;

use anyhow::Result;
use clap::Parser;

use cli::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        cli::Command::Decrypt(args) => commands::decrypt::run(args),
        cli::Command::Encrypt(args) => commands::encrypt::run(args),
        cli::Command::Edit(args) => commands::edit::run(args),
        cli::Command::Rm(args) => commands::rm::run(args),
        cli::Command::Status => commands::status::run(),
        cli::Command::Keys(sub) => match sub.command {
            cli::KeysCommand::Show => commands::keys::show::run(),
            cli::KeysCommand::Import => commands::keys::import::run(),
            cli::KeysCommand::Rotate(args) => commands::keys::rotate::run(args),
        },
        cli::Command::Setup(sub) => match sub.command {
            cli::SetupCommand::Init => commands::setup::init::run(),
            cli::SetupCommand::Nuke => commands::setup::nuke::run(),
            cli::SetupCommand::Completions(args) => commands::setup::completions::run(args),
        },
        cli::Command::Manual => manual::print_and_exit(),
    }
}
