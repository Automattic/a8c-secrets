/// Print the extended man-page-style manual.
pub fn print() {
    print!("{MANUAL}");
}

const MANUAL: &str = r"a8c-secrets — Encrypted secrets management for Automattic mobile repositories

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
        ├── keys.pub                 Public keys (dev + CI), one per line
        ├── google-services.json.age
        └── api-keys.yml.age

    On the developer's machine (never in git):

        ~/.a8c-secrets/
        ├── keys/                    Directory mode 0700
        │   └── <host>/<org>/<name>.key   Private key, file mode 0600
        └── <host>/<org>/<name>/          Decrypted secret files
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
        a8c-secrets keys import   # Paste the dev private key from Secret Store when prompted
        a8c-secrets decrypt

    3. Daily workflow:

        a8c-secrets decrypt          # Get latest secrets after git pull
        a8c-secrets edit config.json # Edit a secret, auto-encrypts on save
        a8c-secrets encrypt          # Encrypt any modified files
        git add .a8c-secrets/        # Commit encrypted changes

    decrypt never prompts for a private key; run keys import first (or set
    A8C_SECRETS_IDENTITY in CI).

    Orphan plaintext (after decrypt): if a decrypted file still exists under
    ~/.a8c-secrets/<host>/<org>/<name>/ but its .age was removed from the repo, decrypt
    lists it. If stdin is a terminal and --non-interactive is not set, it asks before
    deleting those local copies. Otherwise (stdin not a terminal, or
    --non-interactive), they are removed automatically without prompting.

    setup init and keys rotate require stdout connected to a terminal (private keys
    are printed; do not redirect). keys rotate also needs stdin for prompts. setup
    nuke and rm (without --non-interactive) need stdin for confirmation. edit uses
    $EDITOR and prompts; intended for interactive use.

    If stdout is not a terminal, private key blocks are redacted in output (defense in
    depth); still run init/rotate in a real terminal to copy keys.

COMMANDS
    Daily operations:
        decrypt [--non-interactive]       Decrypt .age files to ~/.a8c-secrets/<host>/<org>/<name>/
        encrypt [file ...] [--force]      Encrypt modified secrets back to .age
        edit <file>                       Open in $EDITOR, encrypt if changed (TTY required)
        rm <file>                         Remove secret (plaintext + .age)
        status                            Show sync state of all files

    Key management:
        keys show                         Display key paths and keys.pub recipients
        keys import                       Import private key from Secret Store
        keys rotate                       Rotate one keys.pub recipient (interactive), re-encrypt .age files

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

    Secret Store entry names (typical convention; <host>/<org>/<name> is the repo identifier):
        a8c-secrets dev private key for <host>/<org>/<name>
        a8c-secrets CI private key for <host>/<org>/<name>

    The tool identifies which key is yours by deriving the public key from
    your local private key and matching it against entries in keys.pub.
    `keys show` prefixes that entry with 🔑 and prints a legend; other
    recipient lines use spacing only so columns stay aligned.
    Lines starting with # in keys.pub are treated as comments and ignored
    (same as age recipient files); they are optional human notes only.

    Key rotation (employee offboarding):
        1. a8c-secrets keys rotate   # interactive: pick recipient, confirm, then follow printed steps
        2. Update the appropriate Secret Store / CI secret with the new private key (as instructed)
        3. Rotate actual secret values (API keys, tokens) — manual step
        4. Commit updated keys.pub and .age files
        5. Team runs: a8c-secrets keys import && a8c-secrets decrypt

ENVIRONMENT VARIABLES
    A8C_SECRETS_IDENTITY
        Override the private key using an AGE-SECRET-KEY-... string.
        The value is used directly in memory (never written to disk).
        Intended for CI environments.

    EDITOR
        Editor for the `edit` command. Parsed like shell words (program plus
        optional arguments; use quotes for paths containing spaces). Default:
        vi (Unix) or notepad (Windows).

FILES
    .a8c-secrets/keys.pub          Public keys (committed)
    .a8c-secrets/*.age             Encrypted secrets (committed)
    ~/.a8c-secrets/keys/<host>/<org>/<name>.key Dev private key (local, mode 0600)
    ~/.a8c-secrets/<host>/<org>/<name>/*        Decrypted secrets (local)

SEE ALSO
    `age` specification:     https://age-encryption.org/v1
    `age` (Go reference):    https://github.com/FiloSottile/age
    `age` crate (Rust):      https://docs.rs/age/latest/age/
    rage (Rust `age` CLI):   https://github.com/str4d/rage
    Secret Store:            https://mc.a8c.com/secret-store/
";
