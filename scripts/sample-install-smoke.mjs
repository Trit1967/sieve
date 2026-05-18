// SPDX-License-Identifier: MIT OR Apache-2.0
// Smoke-test the published package shape from local build artifacts.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, cpSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const node = process.execPath;
const wasmPack =
  process.env.WASM_PACK ??
  path.join(homedir(), ".cargo", "bin", process.platform === "win32" ? "wasm-pack.exe" : "wasm-pack");

function run(bin, args, cwd) {
  return execFileSync(bin, args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${path.dirname(wasmPack)}${path.delimiter}${process.env.PATH ?? ""}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function shellQuote(s) {
  const value = String(s);
  if (!/[\s&()^|<>]/.test(value)) {
    return value;
  }
  return `"${value.replaceAll('"', '\\"')}"`;
}

function runNpm(args, cwd) {
  if (process.platform === "win32") {
    return run("cmd.exe", ["/d", "/s", "/c", ["npm", ...args.map(shellQuote)].join(" ")], cwd);
  }
  return run("npm", args, cwd);
}

const tmp = mkdtempSync(path.join(tmpdir(), "sieve-sample-install-"));

try {
  if (!existsSync(wasmPack)) {
    throw new Error(`wasm-pack not found; set WASM_PACK or install it at ${wasmPack}`);
  }
  run(wasmPack, ["build", path.join(root, "crates", "sieve-wasm"), "--release", "--target", "nodejs"], root);
  runNpm(["run", "build"], path.join(root, "packages", "nextjs"));

  const wasmSource = path.join(root, "crates", "sieve-wasm", "pkg");
  const wasmPackage = path.join(tmp, "sieve-wasm-pkg");
  cpSync(wasmSource, wasmPackage, { recursive: true });

  const wasmPackageJson = path.join(wasmPackage, "package.json");
  const wasmMeta = JSON.parse(readFileSync(wasmPackageJson, "utf8"));
  wasmMeta.name = "sieve-guard-wasm";
  writeFileSync(wasmPackageJson, `${JSON.stringify(wasmMeta, null, 2)}\n`);

  const packJson = runNpm(["pack", "--pack-destination", tmp, "--json"], path.join(root, "packages", "nextjs"));
  const [{ filename }] = JSON.parse(packJson);
  const nextTarball = path.join(tmp, filename);

  writeFileSync(
    path.join(tmp, "package.json"),
    JSON.stringify({ private: true, type: "module" }, null, 2),
  );
  runNpm(["install", "--no-audit", "--no-fund", wasmPackage, nextTarball], tmp);

  writeFileSync(
    path.join(tmp, "smoke.mjs"),
    `
import { instrumentSystemPrompt, sieveCheck } from "sieve-guard-nextjs";

const verdict = await sieveCheck("You are helpful.", "hello");
if (verdict.decision !== "Allow") {
  throw new Error(\`expected Allow, got \${verdict.decision}\`);
}

const instrumented = await instrumentSystemPrompt("You are helpful.");
const token = instrumented.canary_state.canaries[0];
if (!token || !instrumented.system_prompt.includes(token)) {
  throw new Error("instrumented prompt does not contain canary token");
}

console.log("sample install smoke passed");
`,
  );

  run(node, [path.join(tmp, "smoke.mjs")], tmp);
  console.log(`sample install smoke passed in ${tmp}`);
} finally {
  if (!process.env.SIEVE_KEEP_SAMPLE_SMOKE) {
    rmSync(tmp, { recursive: true, force: true });
  }
}
