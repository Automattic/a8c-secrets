use crate::models::SecretFileName;
use clap::{Parser, Subcommand};
use clap_complete::Shell;

/// Manage encrypted secrets in Automattic mobile repositories.
///
/// Wraps the `age` encryption library to encrypt/decrypt secret files,
/// keeping decrypted secrets outside the repository working tree in
/// `~/.a8c-secrets/<host>/<org>/<name>/`, protecting them from accidental commits.
///
/// Use `a8c-secrets manual` for a comprehensive guide.
#[derive(Debug, Parser)]
#[command(
    name = "a8c-secrets",
    version,
    after_long_help = "\
TERMINOLOGY:
  \"Private key\" corresponds to what age calls an \"identity\" (AGE-SECRET-KEY-...).
  \"Public key\" corresponds to what age calls a \"recipient\" (age1...).

ENVIRONMENT:
  A8C_SECRETS_IDENTITY    Private key override (AGE-SECRET-KEY-... text only),
                          used directly in memory. Intended for CI (Buildkite)."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Decrypt all secret files into `~/.a8c-secrets/<host>/<org>/<name>/`
    #[command(
        long_about = "\
Decrypt all .age files from .a8c-secrets/ into ~/.a8c-secrets/<host>/<org>/<name>/.

Requires a private key: the local file from `a8c-secrets keys import`, or
A8C_SECRETS_IDENTITY (typical in CI). If no key is available, the command fails with
a hint to import or set the variable.

If any file cannot be decrypted (wrong key, corrupt ciphertext), the command exits
with a non-zero status after attempting every file.

Orphan plaintext: if a file exists under ~/.a8c-secrets/<host>/<org>/<name>/ but its matching
.age was removed from the repo (secret dropped from git), decrypt lists these
orphans. When stdin is a terminal and --non-interactive is not set, you are prompted
before they are deleted. Otherwise (stdin not a terminal, or --non-interactive),
orphan files are removed automatically without prompting.",
        after_long_help = "\
EXAMPLES:
  a8c-secrets decrypt                    # Local: use key from keys import
  a8c-secrets decrypt --non-interactive  # CI: set A8C_SECRETS_IDENTITY; orphans removed without asking

ENVIRONMENT:
  A8C_SECRETS_IDENTITY    Overrides the private key (see top-level --help)"
    )]
    Decrypt(DecryptArgs),

    /// Encrypt modified secret files back into the repository
    #[command(
        long_about = "\
Encrypt secret files from ~/.a8c-secrets/<host>/<org>/<name>/ into .a8c-secrets/*.age.

Uses smart comparison by default: decrypts existing .age files in memory and
compares byte-for-byte against decrypted plaintext files. Only re-encrypts if content
differs. This avoids noisy git diffs since age uses random nonces (encrypting
the same content twice produces different ciphertext).

Encrypts to ALL public keys in .a8c-secrets/keys.pub (both dev and CI).",
        after_long_help = "\
EXAMPLES:
  a8c-secrets encrypt                # Smart-encrypt all files
  a8c-secrets encrypt api-keys.yml   # Smart-encrypt a specific file
  a8c-secrets encrypt --force        # Re-encrypt everything (after key rotation)

NOTES:
  Smart comparison requires the private key to decrypt .age files. If missing,
  use --force or run `a8c-secrets keys import` first."
    )]
    Encrypt(EncryptArgs),

    /// Open a secret file in $EDITOR, encrypting on save if changed
    #[command(
        long_about = "\
Open a secret file in your editor for modification.

Opens ~/.a8c-secrets/<host>/<org>/<name>/<file> in $EDITOR (default: vi on Unix / notepad on Windows). The value is parsed
like shell words (program plus optional arguments; quote paths that contain spaces).
Compares file content before and after the editor session — only encrypts if changed.
If the file doesn't exist, prompts to create it.

Requires stdin connected to a terminal for prompts (same idea as `rm` without
--non-interactive).",
        after_long_help = "\
EXAMPLES:
  a8c-secrets edit google-services.json   # Edit an existing secret
  a8c-secrets edit new-config.yml         # Create and edit a new secret
  EDITOR=code a8c-secrets edit api.json   # Use VS Code as editor
  EDITOR='code --wait' a8c-secrets edit api.json   # VS Code with flags (shell word splitting)"
    )]
    Edit(EditArgs),

    /// Remove a secret file (both plaintext and .age)
    #[command(
        long_about = "\
Remove a secret file completely.

Deletes both the decrypted file at ~/.a8c-secrets/<host>/<org>/<name>/<file> and the
encrypted file at .a8c-secrets/<file>.age. Prompts for confirmation unless
--non-interactive is provided.

When run without --non-interactive, stdin must be a terminal so you can confirm
the deletion. In non-interactive environments (for example CI), pass
--non-interactive explicitly.",
        after_long_help = "\
EXAMPLES:
  a8c-secrets rm old-api-key.json
  a8c-secrets rm --non-interactive old-api-key.json"
    )]
    Rm(RmArgs),

    /// Show sync status of all secret files
    #[command(long_about = "\
Show the sync status of all secret files.

Displays the repo identifier, how many public keys were read from keys.pub (2 expected),
private key status, each file as a compact emoji triplet (📝 plaintext · 🔏 .age · ✅/❌/❓),
and a legend explaining the rows. Example in-sync row: 📝✅🔏  config.json")]
    Status,

    /// Key management (show, import, rotate)
    Keys(KeysSub),

    /// Initial setup and maintenance
    Setup(SetupSub),

    /// Print a comprehensive man-page-style guide
    Manual,
}

// -- Daily operation args --

#[derive(Debug, clap::Args)]
pub struct DecryptArgs {
    /// Never prompt before removing orphan plaintext; same as when stdin is not a
    /// terminal.
    #[arg(long)]
    pub non_interactive: bool,
}

#[derive(Debug, clap::Args)]
pub struct EncryptArgs {
    /// Specific files to encrypt. If omitted, considers all files.
    pub files: Vec<SecretFileName>,

    /// Skip smart comparison and re-encrypt unconditionally.
    /// Use after key rotation.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, clap::Args)]
pub struct EditArgs {
    /// Name of the secret file to edit (e.g. "google-services.json")
    pub file: SecretFileName,
}

#[derive(Debug, clap::Args)]
pub struct RmArgs {
    /// Skip confirmation prompt.
    #[arg(long)]
    pub non_interactive: bool,

    /// Name of the secret file to remove
    pub file: SecretFileName,
}

// -- Keys subcommands --

#[derive(Debug, clap::Args)]
pub struct KeysSub {
    #[command(subcommand)]
    pub command: KeysCommand,
}

#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Display private key path and public keys from keys.pub
    #[command(long_about = "\
Display key information for the current repository.

Shows the private key file path, derives the corresponding public key,
and lists all public keys from .a8c-secrets/keys.pub.")]
    Show,

    /// Import a private key from the Secret Store
    #[command(long_about = "\
Import a dev private key from the Automattic Secret Store.

Prompts you to paste the private key string (AGE-SECRET-KEY-...) and saves
it to ~/.a8c-secrets/keys/<host>/<org>/<name>.key with mode 0600. Overwrites any existing
key for this repo identifier.")]
    Import,

    /// Generate a new key pair and re-encrypt all files
    #[command(
        long_about = "\
Rotate one recipient in keys.pub: pick which public key to replace from an
interactive list, confirm with y/N, then generate a new key pair, update keys.pub in place
(preserving comments), and re-encrypt each .age file under .a8c-secrets/ using the matching
plaintext under ~/.a8c-secrets/<host>/<org>/<name>/ (every file must already be in sync, i.e.
show the 📝✅🔏 status in `a8c-secrets status`).

Requires a local private key that matches at least one line in keys.pub.
After rotation, prints the new private key and next steps (Secret Store /
CI secrets depending on whether you rotated the key you hold locally).

Recommended: run this before encrypting and pushing new provider/API secrets, so new material
is not encrypted to recipients who should no longer have the old dev key. Still revoke or
replace credentials at each provider as your process requires — this command does not expire
API keys. After rotation, update secret file content and run encrypt (often --force) when you
change provider material.

Requires stdout connected to a terminal so the new private key is shown on screen
(do not redirect stdout). Requires stdin connected to a terminal for interactive prompts.",
        after_long_help = "\
EXAMPLE:
  a8c-secrets keys rotate"
    )]
    Rotate,
}

// -- Setup subcommands --

#[derive(Debug, clap::Args)]
pub struct SetupSub {
    #[command(subcommand)]
    pub command: SetupCommand,
}

#[derive(Debug, Subcommand)]
pub enum SetupCommand {
    /// Initialize a8c-secrets in the current repository
    #[command(long_about = "\
Initialize a8c-secrets in the current git repository.

Creates .a8c-secrets/keys.pub, generates both dev and CI key pairs, and saves
the dev private key locally. Derives the repo identifier from git remote `origin`
and fails if auto-detection is unavailable.

Requires stdout connected to a terminal so private keys are shown on screen (do not
redirect or capture stdout).")]
    Init,

    /// Remove all a8c-secrets data (repo files, local keys, decrypted files)
    #[command(long_about = "\
Completely remove a8c-secrets from the repository and local machine.

Deletes .a8c-secrets/ from the repo, the private key at
~/.a8c-secrets/keys/<host>/<org>/<name>.key, and all decrypted files at
~/.a8c-secrets/<host>/<org>/<name>/. Requires typing the repo identifier to confirm.

Requires stdout connected to a terminal so the destructive summary is visible (do not
redirect stdout). Requires stdin connected to a terminal to type the confirmation.")]
    Nuke,

    /// Output shell completion script
    #[command(after_long_help = "\
EXAMPLES:
  a8c-secrets setup completions bash >> ~/.bashrc
  a8c-secrets setup completions zsh > ~/.zfunc/_a8c-secrets
  a8c-secrets setup completions fish > ~/.config/fish/completions/a8c-secrets.fish")]
    Completions(CompletionsArgs),
}

#[derive(Debug, clap::Args)]
pub struct CompletionsArgs {
    /// Target shell
    pub shell: Shell,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("a8c-secrets").chain(args.iter().copied()))
    }

    #[test]
    fn parse_decrypt() {
        let cli = parse(&["decrypt"]).unwrap();
        assert!(matches!(cli.command, Command::Decrypt(_)));
    }

    #[test]
    fn parse_decrypt_non_interactive() {
        let cli = parse(&["decrypt", "--non-interactive"]).unwrap();
        if let Command::Decrypt(args) = cli.command {
            assert!(args.non_interactive);
        } else {
            panic!("expected Decrypt");
        }
    }

    #[test]
    fn parse_encrypt_with_files_and_force() {
        let cli = parse(&["encrypt", "--force", "a.json", "b.yml"]).unwrap();
        if let Command::Encrypt(args) = cli.command {
            assert!(args.force);
            assert_eq!(
                args.files,
                vec![
                    SecretFileName::try_from("a.json").unwrap(),
                    SecretFileName::try_from("b.yml").unwrap(),
                ]
            );
        } else {
            panic!("expected Encrypt");
        }
    }

    #[test]
    fn parse_encrypt_defaults() {
        let cli = parse(&["encrypt"]).unwrap();
        if let Command::Encrypt(args) = cli.command {
            assert!(!args.force);
            assert!(args.files.is_empty());
        } else {
            panic!("expected Encrypt");
        }
    }

    #[test]
    fn parse_edit() {
        let cli = parse(&["edit", "secret.json"]).unwrap();
        if let Command::Edit(args) = cli.command {
            assert_eq!(args.file, SecretFileName::try_from("secret.json").unwrap());
        } else {
            panic!("expected Edit");
        }
    }

    #[test]
    fn parse_edit_missing_file_errors() {
        let err = parse(&["edit"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn parse_rm_non_interactive() {
        let cli = parse(&["rm", "--non-interactive", "secret.json"]).unwrap();
        if let Command::Rm(args) = cli.command {
            assert!(args.non_interactive);
            assert_eq!(args.file, SecretFileName::try_from("secret.json").unwrap());
        } else {
            panic!("expected Rm");
        }
    }

    #[test]
    fn parse_keys_rotate() {
        let cli = parse(&["keys", "rotate"]).unwrap();
        if let Command::Keys(sub) = cli.command {
            assert!(matches!(sub.command, KeysCommand::Rotate));
        } else {
            panic!("expected Keys");
        }
    }

    #[test]
    fn parse_no_subcommand_errors() {
        let err = parse(&[]).unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn parse_manual() {
        let cli = parse(&["manual"]).unwrap();
        assert!(matches!(cli.command, Command::Manual));
    }
}
