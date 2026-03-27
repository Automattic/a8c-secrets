/// Print the extended man-page-style manual.
pub fn print() {
    print!("{MANUAL}");
}

const MANUAL: &str = r#"a8c-secrets — Encrypted secrets management for Automattic mobile repositories

OVERVIEW
    a8c-secrets wraps the `age` encryption library (https://age-encryption.org/v1)
    to manage encrypted secret files (API keys, service accounts, certificates)
    in git repositories.

    Decrypted secrets live OUTSIDE the repo working tree in ~/.a8c-secrets/,
    protecting them from accidental commits and AI agent access.

TERMINOLOGY
    a8c-secrets          `age` equivalent   Format
    ──────────────────   ────────────────   ──────────────────
    private key          identity           AGE-SECRET-KEY-1...
    public key           recipient          age1...

FILE LAYOUT
    In the repository (committed to git):

        .a8c-secrets/
        ├── config.toml              repo = "<slug>"
        ├── keys.pub                 Public keys (dev + CI), one per line
        ├── google-services.json.age
        └── api-keys.yml.age

    On the developer's machine (never in git):

        ~/.a8c-secrets/
        ├── keys/                    Directory mode 0700
        │   └── <repo>.key          Private key, file mode 0600
        └── <repo>/                  Decrypted secret files
            ├── google-services.json
            └── api-keys.yml

SECRET FILE NAMES
    Use one path segment per secret (e.g. Secrets.swift), not a relative path.
    Commands that take a secret name (edit, encrypt with explicit files, rm)
    reject paths, .., and directory separators so files stay under the
    intended directories.

GETTING STARTED
    1. First-time repo setup (run once by a maintainer):

        cd my-repo
        a8c-secrets setup init
        # Follow the printed instructions for Secret Store + Buildkite

    2. Developer onboarding:

        cd my-repo
        a8c-secrets decrypt
        # Paste the dev private key from Secret Store when prompted

    3. Daily workflow:

        a8c-secrets decrypt          # Get latest secrets after git pull
        a8c-secrets edit config.json # Edit a secret, auto-encrypts on save
        a8c-secrets encrypt          # Encrypt any modified files
        git add .a8c-secrets/        # Commit encrypted changes

COMMANDS
    Daily operations:
        decrypt [--non-interactive]       Decrypt .age files to ~/.a8c-secrets/<repo>/
        encrypt [file ...] [--force]      Encrypt modified secrets back to .age
        edit <file>                       Open in $EDITOR, encrypt if changed
        rm <file>                         Remove secret (plaintext + .age)
        status                            Show sync state of all files

    Key management:
        keys show                         Display key info and dev/CI identification
        keys import                       Import private key from Secret Store
        keys rotate --dev|--ci            Rotate a key pair, re-encrypt all files

    Setup:
        setup init                        Initialize a8c-secrets in a repository
        setup nuke                        Remove all a8c-secrets data
        setup completions <shell>         Output shell completion script

SMART ENCRYPTION
    The encrypt command uses smart comparison by default: it decrypts each
    existing .age file in memory and compares byte-for-byte with the local
    plaintext. Only files whose content actually changed get re-encrypted.

    This matters because `age` uses random nonces — encrypting the same content
    twice produces different ciphertext, which would create noisy git diffs.

    Use --force to skip comparison and re-encrypt everything (e.g., after
    key rotation when the old key can no longer decrypt).

KEY MANAGEMENT
    Each repo has two `age` key pairs:

        dev   Shared by all developers. Private key in Secret Store.
        ci    Used by CI agents (Buildkite). Private key in Buildkite secrets.

    The tool identifies which key is "dev" by deriving the public key from
    your local private key and matching it against entries in keys.pub.
    Comment labels (# dev, # ci) are for humans — the tool doesn't rely on them.

    Key rotation (employee offboarding):
        1. a8c-secrets keys rotate --dev
        2. Update Secret Store with the new dev private key
        3. Rotate actual secret values (API keys, tokens) — manual step
        4. Commit updated keys.pub and .age files
        5. Team runs: a8c-secrets keys import && a8c-secrets decrypt

ENVIRONMENT VARIABLES
    A8C_SECRETS_IDENTITY
        Override the private key. If the value starts with AGE-SECRET-KEY-,
        it is used directly in memory (never written to disk). Otherwise it
        is treated as a file path. Intended for CI environments.

    EDITOR
        Editor for the `edit` command. Default: vi (Unix) or notepad (Windows).

FILES
    .a8c-secrets/config.toml       Repo slug (committed)
    .a8c-secrets/keys.pub          Public keys (committed)
    .a8c-secrets/*.age             Encrypted secrets (committed)
    ~/.a8c-secrets/keys/<repo>.key Dev private key (local, mode 0600)
    ~/.a8c-secrets/<repo>/*        Decrypted secrets (local)

SEE ALSO
    `age` specification:     https://age-encryption.org/v1
    `age` (Go reference):    https://github.com/FiloSottile/age
    `age` crate (Rust):      https://docs.rs/age/latest/age/
    rage (Rust `age` CLI):   https://github.com/str4d/rage
    Secret Store:            https://mc.a8c.com/secret-store/
"#;
