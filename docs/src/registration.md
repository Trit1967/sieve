# Registration

Use publishable package names that match the installation path.

| Registry | Package | Import / command | Status checked |
|---|---|---|---|
| crates.io | `sieve-core` | `use sieve_core::Scanner;` | Available |
| crates.io | `sieve-cli` | `cargo install sieve-cli` | Available |
| PyPI | `sieve-guard` | `import sieve` | Available |
| npm | `sieve-guard-wasm` | `import { Scanner } from "sieve-guard-wasm";` | Available |
| npm | `sieve-guard-nextjs` | `import { sieveCheck } from "sieve-guard-nextjs";` | Available |

Do not publish the Python distribution as `sieve`: that name already belongs
to an unrelated XML comparison package on PyPI. The distribution name should be
`sieve-guard`; the Python module remains `sieve` so application code stays
short.

Do not depend on the `@sieve/*` npm scope unless the scope is registered and
controlled by the project. The unscoped npm names avoid that extra registration
step.

## First Publish Checklist

1. crates.io: create or rotate `CRATES_IO_TOKEN`.
2. PyPI: create the `sieve-guard` project through the trusted publisher flow.
3. npm: create an automation token with publish rights for
   `sieve-guard-wasm` and `sieve-guard-nextjs`.
4. GitHub repository secrets: set `CRATES_IO_TOKEN` and `NPM_TOKEN`.
5. GitHub Pages: enable `Settings -> Pages -> Build and deployment -> Source:
   GitHub Actions`.
