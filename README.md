# a8c-secrets

`a8c-secrets` is a CLI tool for managing encrypted secrets in Automattic mobile and desktop repositories.

It is aimed to make it easy to deal with secret files that are needed for developers and CI to **compile** the code in the repository with real credentials/secret files (`secrets.properties`, `Secrets.swift`, …)

Internally, it uses the [`age`](https://age-encryption.org/v1) encryption specification to encrypt/decrypt secret files, and offers some additional key features compared to using [the official `age` binary](https://github.com/FiloSottile/age) directly:
 - It decrypts all the secrets present in a repository using a single `a8c-secrets decrypt` command (compared to having to call the official `age` binary on each file one by one)
 - It automatically manages the public and private keys in the right places on the user's computer (compared to users having to provide the key to the official `age` command line explicitly)
 - It ensures the secrets are decrypted **outside** the repository working tree (in `~/.a8c-secrets/<host>/<org>/<name>/`), to avoid accidental commits of secrets and reduce access from AI agents running in repo.
 - It provides help messages tailored to our usage of the tool at Automattic (references to Secrets Store, dedicated help messages…)

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Automattic/a8c-secrets/main/install.sh | bash
```

Or install to a custom directory:

```sh
curl -fsSL https://raw.githubusercontent.com/Automattic/a8c-secrets/main/install.sh | bash -s -- --prefix ~/.local/bin
```

## Quick start

**First-time repo setup** (run once by a maintainer):

```sh
cd my-repo
a8c-secrets setup init
# Follow the printed instructions for Secret Store + Buildkite
```

**Developer onboarding:**

```sh
cd my-repo
a8c-secrets keys import   # Paste the dev private key from Secret Store when prompted
a8c-secrets decrypt
```

**Daily workflow:**

```sh
a8c-secrets decrypt          # Get latest secrets after git pull
a8c-secrets edit config.json # Edit a secret, auto-encrypts on save
a8c-secrets encrypt          # Encrypt any modified files
git add .a8c-secrets/        # Commit encrypted changes
```

Run `a8c-secrets manual` for a comprehensive guide, or `a8c-secrets help <command>` for per-command help.

## What gets encrypted

> [!NOTE]
> The secrets this tool manages are files needed by Automatticians to compile apps locally and by CI — for example `secret.properties` (Android), `Secrets.swift` (iOS), API keys, or debug signing identities.
>
> Secrets only needed by CI (e.g. App Store signing identities, Play Store upload keys) should **not** go through this tool — use Buildkite secret environment variables instead.

## File layout

```
In the repo (committed):              On the developer's machine (never in git):

.a8c-secrets/                          ~/.a8c-secrets/
├── keys.pub            public keys    ├── keys/
├── secret.json.age     encrypted      │   └── <host>/<org>/<name>.key  private key (0600)
└── api-keys.yml.age    encrypted      └── <host>/<org>/<name>/         decrypted files
                                           └── api-keys.yml
```

## Design decisions

### Why Rust?
Cross-platform binaries (macOS, Linux, Windows) from a single codebase. Existing Buildkite pipeline and team familiarity from the [`git-conceal`](https://github.com/Automattic/git-conceal) project.

### Why `age` as a library, not a CLI subprocess?
Using the [`age` crate](https://docs.rs/age/latest/age/) eliminates the external dependency — users don't need to install `age` separately, and there's no PATH injection risk. The crate implements the same [`age-encryption.org/v1`](https://age-encryption.org/v1) spec as the [Go reference implementation](https://github.com/FiloSottile/age). A trait-based abstraction (`CryptoEngine`) allows swapping to a subprocess engine if ever needed.

### Why decrypt outside the working tree?
Decrypted secrets in `~/.a8c-secrets/<host>/<org>/<name>/` can never be accidentally committed (even a `.gitignore` typo can't expose them) and are invisible to AI agents restricted to the repo working copy.

### Two key pairs per repo (dev + CI)
The dev private key is shared by all developers via Secret Store. The CI private key is injected as a Buildkite secret via `A8C_SECRETS_IDENTITY`. Which key is yours is determined by public key derivation (matching your private key against `keys.pub`). Lines starting with `#` in `keys.pub` are comments and are ignored when reading recipients (same as age); they are optional for humans only.

### Secret Store entry names
Those are human-created. Replace `<host>/<org>/<name>` with your repo identifier:
 - dev private key → `a8c-secrets dev private key for <host>/<org>/<name>`
 - CI private key → `a8c-secrets CI private key for <host>/<org>/<name>`.

### Smart encryption
Since `age` uses random nonces, encrypting identical content twice produces different ciphertext. The `encrypt` command decrypts existing `.age` files in memory and compares byte-for-byte with decrypted plaintext, only re-encrypting when content actually changed. This prevents noisy git diffs.
Use `--force` after key rotation to bypass the smart comparison and re-encrypt files unconditionally.

### Flat file structure
No subdirectories inside `.a8c-secrets/`. Name collisions (e.g. two `google-services.json` for different modules) are handled with unique flat names like `wear-google-services.json`.

### Secret file names
Each secret is a single filename (e.g. `Secrets.swift`), not a relative path. The `edit`, `encrypt <file …>`, and `rm` commands reject names that contain path separators, `..`, or other non-flat syntax so outputs stay under `.a8c-secrets/` and `~/.a8c-secrets/<host>/<org>/<name>/`.

### Memory hygiene
Decrypted file contents are held in [`zeroize`](https://docs.rs/zeroize/) buffers where practical so they are cleared when dropped. In-memory private keys are represented as [`age::x25519::Identity`](https://docs.rs/age/latest/age/x25519/struct.Identity.html), which wraps secret material with age’s own zeroizing discipline.

### `decrypt` and orphan plaintext files
If a file still exists under `~/.a8c-secrets/<host>/<org>/<name>/` but its `.age` was removed from the repository (for example the team deleted a secret from git), `decrypt` reports these as orphans.
 - If stdin is connected to an interactive terminal and `--non-interactive` is not set: the tool will **prompt before deleting**. This is for when a developer runs the command locally, to avoid accidentally removing e.g. a plaintext secret they just added and forgot to encrypt (and commit the `.age`) first.
 - If stdin is not an interactive terminal, or `--non-interactive` is set (typical CI): orphan files are removed automatically **without prompting**. That keeps CI from blocking on a prompt; those environments also typically should not keep extra unencrypted plaintext around.

Use `decrypt --non-interactive` in CI with `A8C_SECRETS_IDENTITY` (or a key file on the agent).

### Terminals, prompts, and private keys on stdout
- **`setup init`** and **`keys rotate`** require **stdout** connected to a terminal so new private keys are not accidentally written to a file or pipe. `keys rotate` also needs **stdin** for its menus and confirmations.
- **`setup nuke`** requires **stdout** and **stdin** connected to a terminal (you must see the destructive summary before confirming). **`rm`** (without `--non-interactive`) requires **stdin** for confirmation prompts.
- **`decrypt`** orphan handling uses **stdin** for the orphan prompt (unless `--non-interactive` is set or stdin is not an interactive terminal — see above).
- **`edit`** is for interactive use (`$EDITOR`, optional create prompt).

## Key rotation

On employee offboarding (or when rotating CI’s key), treat **age keys** (`keys.pub` / dev & CI identities) and **provider/API secrets** (what lives inside the encrypted files) as separate work.

### What `keys rotate` does

It refuses to run until **`a8c-secrets status` shows every secret as “in sync”** (no encrypted-only, decrypted-only, or modified local copy). Then it updates `keys.pub` and **re-encrypts each `.age` file from the matching plaintext under `~/.a8c-secrets/<host>/<org>/<name>/`**, so new ciphertext matches your local decrypted files. If anything is out of sync, fix it with `decrypt` / `encrypt` (or remove stray files) and retry.

### Recommended order

1. **Revoke or disable old credentials** at each provider as soon as your runbook allows (so stolen keys stop working at the API).
2. **Run `a8c-secrets keys rotate`** — interactive: pick the recipient, confirm; the tool prints the new private key and re-encrypts `.age` files from your in-sync plaintext under `~/.a8c-secrets/<host>/<org>/<name>/`.
3. **Update Secret Store / CI** (or equivalent) with the new private key; notify the team to `keys import` when the dev key changed.
4. **Issue new provider credentials if needed**, update the decrypted secret files, then **`a8c-secrets encrypt`** — usually **`--force`** right after a key rotation. Commit `keys.pub` and `.age` changes (and any follow-up commits for new secret content).

**Why age keys before new secrets in git:** if you `encrypt` and push **new** API material while `keys.pub` still includes a recipient who should no longer decrypt, anyone with that old dev key could decrypt that commit. Completing `keys rotate` first avoids encrypting new secrets to the old audience. Diffs right after rotation reflect **new ciphertext for the same plaintext** you had locally (age nonces differ each time), not necessarily new provider values — those show up after you change decrypted files and `encrypt` again.

5. Team runs `a8c-secrets keys import && a8c-secrets decrypt` where needed.

## Environment variables

| Variable | Description |
|---|---|
| `A8C_SECRETS_IDENTITY` | Private key override as `AGE-SECRET-KEY-...` text, used directly in memory. Intended for CI. |
| `EDITOR` | Editor for the `edit` command. Parsed like shell words, so the command may include arguments (e.g. `code --wait`) or a quoted path with spaces. Default: `vi` (Unix) or `notepad` (Windows). |

## Development

Requires **Rust 1.85** or later (matches the [Rust 2024 edition](https://doc.rust-lang.org/edition-guide/rust-2024/index.html) used by this crate).

```sh
make help          # Show all targets
make lint          # Run clippy
make test          # Run tests
make build-release # Build release binary
```

## References

- [`age` specification](https://age-encryption.org/v1)
- [`age` Go reference implementation](https://github.com/FiloSottile/age)
- [`age` Rust crate docs](https://docs.rs/age/latest/age/)
- [rage (Rust `age` CLI)](https://github.com/str4d/rage)
- [Secret Store](https://mc.a8c.com/secret-store/)
