//! `a8c-secrets` CLI entrypoint and command dispatch.
#![warn(missing_docs)]

mod cli;
mod commands;
mod config;
mod crypto;
mod keys;
mod manual;
mod models;
mod permissions;

use anyhow::Result;
use clap::Parser;

use cli::Cli;
use crypto::AgeCrateEngine;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let crypto_engine = AgeCrateEngine::new();

    match cli.command {
        cli::Command::Decrypt(args) => commands::decrypt::run(&crypto_engine, &args),
        cli::Command::Encrypt(args) => commands::encrypt::run(&crypto_engine, &args),
        cli::Command::Edit(args) => commands::edit::run(&crypto_engine, &args),
        cli::Command::Rm(args) => commands::rm::run(&args),
        cli::Command::Status => commands::status::run(&crypto_engine),
        cli::Command::Keys(sub) => match sub.command {
            cli::KeysCommand::Show => commands::keys::show::run(),
            cli::KeysCommand::Import => commands::keys::import::run(),
            cli::KeysCommand::Rotate => commands::keys::rotate::run(&crypto_engine),
        },
        cli::Command::Setup(sub) => match sub.command {
            cli::SetupCommand::Init => commands::setup::init::run(&crypto_engine),
            cli::SetupCommand::Nuke => commands::setup::nuke::run(),
            cli::SetupCommand::Completions(args) => {
                commands::setup::completions::run(&args);
                Ok(())
            }
        },
        cli::Command::Manual => {
            manual::print();
            Ok(())
        }
    }
}
