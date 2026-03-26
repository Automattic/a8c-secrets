# a8c-secrets

`a8c-secrets` is a CLI tool for managing encrypted secrets in Automattic mobile and desktop repositories.

It is aimed to make it easy to deal with secret files that are needed for developers and CI to **compile** the code in the repository with real credentials/secret files (`secrets.properties`, `Secrets.swift`, …)

Internally, it uses the [`age`](https://age-encryption.org/v1) encryption specification to encrypt/decrypt secret files, and offers some additional key features compared to using [the official `age` binary](https://github.com/FiloSottile/age) directly:
 - It decrypts all the secrets present in a repository using a single `a8c-secrets decrypt` command (compared to having to call the official `age` binary on each file one by one)
 - It automatically manages the public and private keys in the right places on the user's computer (compared to users having to provide the key to the official `age` command line explicitly)
 - It ensures the secrets are decrypted **outside** the repository working tree (in `~/.a8c-secrets/<repo>/`), to avoid accidental commits of secrets and reduce access from AI agents running in repo.
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
a8c-secrets decrypt
# Paste the dev private key from Secret Store when prompted
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
├── config.toml         repo slug      ├── keys/
├── keys.pub            public keys    │   └── <repo>.key    private key (0600)
├── secret.json.age     encrypted      └── <repo>/           decrypted files
└── api-keys.yml.age    encrypted          ├── secret.json
                                           └── api-keys.yml
```

## Design decisions

**Why Rust?** Cross-platform binaries (macOS, Linux, Windows) from a single codebase. Existing Buildkite pipeline and team familiarity from the [`git-conceal`](https://github.com/Automattic/git-conceal) project.

**Why `age` as a library, not a CLI subprocess?** Using the [`age` crate](https://docs.rs/age/latest/age/) eliminates the external dependency — users don't need to install `age` separately, and there's no PATH injection risk. The crate implements the same [`age-encryption.org/v1`](https://age-encryption.org/v1) spec as the [Go reference implementation](https://github.com/FiloSottile/age). A trait-based abstraction (`CryptoEngine`) allows swapping to a subprocess engine if ever needed.

**Why decrypt outside the working tree?** Decrypted secrets in `~/.a8c-secrets/<repo>/` can never be accidentally committed (even a `.gitignore` typo can't expose them) and are invisible to AI agents restricted to the repo working copy.

**Two key pairs per repo (dev + CI).** The dev private key is shared by all developers via Secret Store. The CI private key is injected as a Buildkite secret via `A8C_SECRETS_IDENTITY`. Key identification uses public key derivation (matching your private key against `keys.pub`), not comment labels — so `# dev` / `# ci` comments are for humans only.

**Smart encryption.** Since `age` uses random nonces, encrypting identical content twice produces different ciphertext. The `encrypt` command decrypts existing `.age` files in memory and compares byte-for-byte with local plaintext, only re-encrypting when content actually changed. This prevents noisy git diffs. Use `--force` after key rotation.

**Flat file structure.** No subdirectories inside `.a8c-secrets/`. Name collisions (e.g. two `google-services.json` for different modules) are handled with unique flat names like `wear-google-services.json`.

## Key rotation

On employee offboarding:

1. `a8c-secrets keys rotate --dev`
2. Update Secret Store with the new dev private key
3. Rotate the actual secret values (API keys, tokens) — this is a manual step outside the tool's scope
4. Commit updated `keys.pub` and `.age` files
5. Team runs: `a8c-secrets keys import && a8c-secrets decrypt`

## Environment variables

| Variable | Description |
|---|---|
| `A8C_SECRETS_IDENTITY` | Private key override. If value starts with `AGE-SECRET-KEY-`, used directly in memory. Otherwise treated as a file path. Intended for CI. |
| `EDITOR` | Editor for the `edit` command. Default: `vi` (Unix) or `notepad` (Windows). |

## Development

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
