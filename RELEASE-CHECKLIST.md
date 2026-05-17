# Release checklist — sieve v0.3.0

Status: code + CHANGELOG + version bumps committed; the release is
blocked on three secrets in the `Trit1967/sieve` GitHub repo. Once
those are rotated, one `gh workflow run` triggers publish to crates.io,
npm, and PyPI in parallel.

## TL;DR — what only YOU can do

These three secrets must be rotated (5 minutes total):

| Secret name | Where to set it | How to get a new value |
|---|---|---|
| `CRATES_IO_TOKEN` | `Trit1967/sieve` → Settings → Secrets → Actions | https://crates.io/me → New Token (any name; scope `publish-new` + `publish-update`) |
| `NPM_TOKEN` | same | https://www.npmjs.com/settings/&lt;user&gt;/tokens → Generate New Token → Automation |
| (PyPI) | https://pypi.org/manage/account/publishing/ | Configure a **Trusted Publisher** for the `sieve` project pointing at workflow `release.yml` in `Trit1967/sieve`. No secret needed — uses OIDC. |

Then trigger the release:

```bash
gh workflow run release.yml --repo Trit1967/sieve --ref main -f ref=v0.3.0
```

Everything below is what I've already done so you don't have to.

## What's already prepped (code-side)

- [x] `crates/sieve-core` + bindings: 100% catch on 3520 probes,
  3.5% FPR, all 240 tests green.
- [x] `Cargo.toml` workspace `version` bumped to `0.3.0`.
- [x] All path-dep version pins bumped to `0.3.0` across:
  - `crates/sieve-cli/Cargo.toml`
  - `crates/sieve-py/Cargo.toml`
  - `crates/sieve-wasm/Cargo.toml`
  - `examples/rust-basic/Cargo.toml`
  - `benchmarks/harness/Cargo.toml`
- [x] `CHANGELOG.md` `[0.3.0]` section written with headline numbers,
  added/changed/fixed lists.
- [x] `sieve` CLI binary built and smoke-tested
  (`crates/sieve-cli` — `sieve scan` exits 0/1/2 for Allow/Flag/Block).
- [x] WASM build flags fixed (`bulk-memory`, `nontrapping-float-to-int`).
- [x] Workspace `cargo build --workspace` clean.

## Background on why this is blocked

`v0.1.0` shipped on PyPI only (memories from the original release
window). The crates.io publish failed because the
`CRATES_IO_TOKEN` repo secret is a **pre-2020 legacy token** that
crates.io revoked en masse for security reasons (an old PRNG
weakness — see crates.io blog post 2020-07-14). It will keep
failing until you generate a new token.

The npm publish failed in a separate way — `NPM_TOKEN` was
either never set with a real Automation token or expired. Same
fix: generate a fresh Automation-class token and paste it into
the GitHub secret.

PyPI doesn't need a secret on the repo side because the release
workflow uses [trusted publishers](https://docs.pypi.org/trusted-publishers/)
via OIDC. If v0.1.0's PyPI publish worked, your trusted publisher
config is fine and v0.3.0 should publish automatically. If it
didn't, configure one once on pypi.org against `release.yml`.

## Step-by-step

1. **Rotate `CRATES_IO_TOKEN`**:
   - https://crates.io/me → Settings → API Tokens → New Token
   - Name: `sieve-release-2026` (or any)
   - Scopes: `publish-new`, `publish-update`
   - Crates: scope to `sieve-core` if you want to be strict, or leave wildcard
   - Copy the token value (you only see it once)
   - https://github.com/Trit1967/sieve/settings/secrets/actions → `CRATES_IO_TOKEN` → Update
   - Paste; save.

2. **Rotate `NPM_TOKEN`**:
   - https://www.npmjs.com/settings/&lt;your-user&gt;/tokens → Generate New Token → Automation
   - Copy the token
   - Same GitHub secrets page → `NPM_TOKEN` → Update

3. **(Once)** Confirm PyPI trusted publisher is configured:
   - https://pypi.org/manage/project/sieve/settings/publishing/
   - Should have an entry for `Trit1967/sieve` workflow `release.yml`
   - If not, add it. No copying needed.

4. **Tag and push**:

   ```bash
   git tag -a v0.3.0 -m "sieve v0.3.0 — 100% catch on 3520 probes"
   git push origin v0.3.0
   ```

5. **Trigger the workflow** (or it'll auto-trigger on tag push):

   ```bash
   gh workflow run release.yml --repo Trit1967/sieve --ref main -f ref=v0.3.0
   gh run watch  # follow the run
   ```

6. **Verify after the run completes**:

   ```bash
   # crates.io
   cargo search sieve-core
   # → should show "sieve-core = "0.3.0"" in results

   # npm
   npm view @sieve/wasm version
   # → 0.3.0
   npm view @sieve/nextjs version
   # → 0.3.0

   # PyPI
   pip index versions sieve
   # → should list 0.3.0
   ```

## If a job fails

Most likely failure modes and fixes:

| Error | Meaning | Fix |
|---|---|---|
| `cargo publish` exit 101, status 401 | crates.io rejected token | token still legacy — see step 1 |
| `npm publish` exit 1, `403 forbidden` | npm token wrong scope | regenerate as **Automation** type, not Read-only |
| `npm publish` exit 1, `payment required` | hit npm free-tier limit | upgrade or wait |
| PyPI `403` or `OIDC failed` | trusted publisher not configured | see step 3 |
| `wasm-pack build` errors | toolchain drift | `rustup update stable && rustup target add wasm32-unknown-unknown` locally to repro |

## Once shipped

- [ ] Tweet / post to relevant channels
- [ ] Update README headline numbers (point at v0.3.0 instead of v0.1.0)
- [ ] Run the JailbreakBench external benchmark (separate task) for an
      independent number
- [ ] Build HTTP sidecar so non-Rust/Python/JS consumers can use it
- [ ] (Optional) Apply for an OWASP-LLM Top-10 defense entry
