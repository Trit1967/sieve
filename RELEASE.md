# Release runbook — sieve v0.1.0

Everything in this repo is built, tested, tagged, and ready to publish.
The final step — pushing to registries — requires your authorization
because it's irreversible: package versions are immutable and names
get squatted forever. Run the commands below when you're ready.

## Status check

```sh
git -C "C:/Projects/prompt injection" log --oneline | head -25
git -C "C:/Projects/prompt injection" tag --list
```

Expect 22 commits and tags `v0.1.0-rc1` + `v0.1.0`.

## Step 1 — Create the GitHub repo and push

```sh
cd "C:/Projects/prompt injection"

# Create the repo on github.com/Trit1967/sieve (private first if you want
# to do a final review before going public; --public to ship now):
gh repo create Trit1967/sieve --public --description \
  "Vendor-neutral, embeddable, offline-first prompt injection defense (Rust + Python + WASM)" \
  --homepage "https://github.com/Trit1967/sieve" \
  --source . --remote origin

# Push branch and tags:
git push -u origin main
git push origin v0.1.0-rc1
git push origin v0.1.0
```

The push of `v0.1.0` triggers `.github/workflows/release.yml`. The
workflow has 4 publish jobs (crates.io / PyPI / 2 npm packages) plus
a GitHub release. Each is gated on a secret:

## Step 2 — Configure publish secrets

In GitHub repo Settings → Secrets and variables → Actions:

| Secret name | Where to get it | Used by |
|---|---|---|
| `CRATES_IO_TOKEN` | `cargo login` once locally then copy `~/.cargo/credentials.toml`, OR generate at https://crates.io/me with `publish-update` scope | `publish-crates-io` job |
| `NPM_TOKEN` | `npm login` then copy `~/.npmrc`, OR generate "Automation" token at https://www.npmjs.com/settings/<you>/tokens | `publish-npm-wasm` + `publish-npm-nextjs` jobs |

PyPI uses OIDC trusted publishing — no token needed, but you must
configure it once at https://pypi.org/manage/project/sieve/settings/publishing/:
- Owner: `Trit1967`
- Repository name: `sieve`
- Workflow filename: `release.yml`
- Environment name: leave blank

## Step 3 — Verify locally before the public push

```sh
# Rust core
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

# Benchmarks (regenerates REPORT.md)
bash benchmarks/run.sh

# Example end-to-end
cargo run --release -p rust-basic
```

Expected: 148 unit + 2 corpus tests green; example prints
`Allow / Block / Block / Block` lines.

## Step 4 — After publishes succeed

```sh
# Confirm artifacts:
curl -s https://crates.io/api/v1/crates/sieve-core | jq '.crate.max_version'
curl -s https://pypi.org/pypi/sieve/json | jq '.info.version'
curl -s https://registry.npmjs.org/@sieve/wasm | jq '."dist-tags".latest'
curl -s https://registry.npmjs.org/@sieve/nextjs | jq '."dist-tags".latest'

# Publish the launch posts (drafts already in launch/):
gh release view v0.1.0 --web   # spot-check the auto-generated release notes
```

## Step 5 — Launch posts

Drafts are pre-written in `launch/`:

- `launch/blog-post.md` — "Why your prompt injection defense doesn't catch zero-width characters"
- `launch/show-hn.md` — Show HN post text
- `launch/tweet-thread.md` — Twitter/X thread

You probably want to read through each before posting — they cite
ACL 2025 numbers and call out specific competitors.

## If something goes wrong

- A crate / wheel / npm name conflict means someone else already
  squatted it. Choose an alternative from DECISIONS.md ADR-0001 and
  bump the workspace + binding metadata accordingly.
- A workflow job fails: read the action log, fix the secret or the
  workflow, push a small fix commit, delete the failed tag, and
  re-tag. The release workflow only ever runs on tags matching the
  regex in release.yml — local-only tags are safe.
- PyPI OIDC misconfiguration: the maturin builds will succeed but
  the upload step fails. Double-check the trusted-publisher settings
  point at `release.yml`.
