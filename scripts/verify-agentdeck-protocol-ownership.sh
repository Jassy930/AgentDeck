#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest_path=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      [[ $# -ge 2 ]] || { echo "FAIL: --root requires a path" >&2; exit 2; }
      repo_root="$(cd "$2" && pwd)"
      shift 2
      ;;
    --manifest)
      [[ $# -ge 2 ]] || { echo "FAIL: --manifest requires a path" >&2; exit 2; }
      manifest_path="$2"
      shift 2
      ;;
    *)
      echo "FAIL: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$manifest_path" ]]; then
  manifest_path="$repo_root/protocol/agentdeck/protocol-ownership.json"
fi

command -v bun >/dev/null 2>&1 || {
  echo "FAIL: bun is required for protocol ownership verification" >&2
  exit 1
}

bun - "$repo_root" "$manifest_path" <<'JS'
import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, join, normalize, relative, resolve, sep } from "node:path";

const [, , rootArgument, manifestArgument] = process.argv;
const root = realpathSync(rootArgument);
const manifestPath = resolve(manifestArgument);

function fail(message) {
  throw new Error(message);
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${label} keys mismatch: expected ${wanted.join(",")}; got ${actual.join(",")}`);
  }
}

function safeRelativePath(path, label) {
  if (typeof path !== "string" || path.length === 0 || isAbsolute(path)) {
    fail(`${label} must be a non-empty relative path`);
  }
  if (path.includes("\\") || normalize(path) !== path || path.split("/").includes("..")) {
    fail(`${label} is not canonical: ${path}`);
  }
  const absolute = resolve(root, path);
  if (absolute !== root && !absolute.startsWith(`${root}${sep}`)) {
    fail(`${label} escapes repository root: ${path}`);
  }
  return absolute;
}

function regularFile(path, label) {
  const absolute = safeRelativePath(path, label);
  const stat = lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`${label} must be a regular non-symlink file: ${path}`);
  }
  return absolute;
}

function directory(path, label) {
  const absolute = safeRelativePath(path, label);
  const stat = lstatSync(absolute);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    fail(`${label} must be a directory: ${path}`);
  }
  return absolute;
}

function regularFilesRecursively(rootPath) {
  const result = [];
  for (const entry of readdirSync(rootPath, { withFileTypes: true })) {
    const absolute = join(rootPath, entry.name);
    if (entry.isSymbolicLink()) fail(`source inventory contains symlink: ${absolute}`);
    if (entry.isDirectory()) result.push(...regularFilesRecursively(absolute));
    else if (entry.isFile()) result.push(absolute);
  }
  return result;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function validateHash(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    fail(`${label} must be a lowercase SHA-256`);
  }
}

function validatePaths(paths, label) {
  if (!Array.isArray(paths)) fail(`${label}.paths must be an array`);
  const sorted = [...paths].sort();
  if (JSON.stringify(paths) !== JSON.stringify(sorted)) {
    fail(`${label}.paths must be sorted`);
  }
  if (new Set(paths).size !== paths.length) {
    fail(`${label}.paths contains duplicates`);
  }
  for (const path of paths) regularFile(path, `${label}.paths`);
}

function groupHash(paths) {
  const digest = createHash("sha256");
  for (const path of paths) {
    const fileHash = sha256(readFileSync(regularFile(path, "owned path")));
    digest.update(`${path}\t${fileHash}\n`);
  }
  return digest.digest("hex");
}

function validateGroup(group, label) {
  exactKeys(group, ["paths", "contentSha256"], label);
  validatePaths(group.paths, label);
  validateHash(group.contentSha256, `${label}.contentSha256`);
  const actual = groupHash(group.paths);
  if (actual !== group.contentSha256) {
    fail(`${label} content drift: expected ${group.contentSha256}; got ${actual}`);
  }
}

const manifestRealPath = realpathSync(manifestPath);
if (manifestRealPath !== root && !manifestRealPath.startsWith(`${root}${sep}`)) {
  fail("manifest must stay inside the repository root");
}
const manifest = JSON.parse(readFileSync(manifestRealPath, "utf8"));
exactKeys(manifest, ["schemaVersion", "sourceInventoryRoots", "axes", "boundaries"], "manifest");
if (manifest.schemaVersion !== 1) fail("manifest.schemaVersion must equal 1");

const requiredSourceInventoryRoots = [
  "Sources/AgentDeckCore/Protocol",
  "Sources/AgentDeckRelayClient/Crypto",
  "Sources/AgentDeckRelayClient/Wire",
  "agentdeck-crypto/src",
  "agentdeck-crypto/tests",
  "agentdeck-protocol/src",
  "protocol/agentdeck/fixtures",
];
if (JSON.stringify(manifest.sourceInventoryRoots) !== JSON.stringify(requiredSourceInventoryRoots)) {
  fail("manifest.sourceInventoryRoots drifted");
}

const anchors = {
  e2ee: {
    versionPath: "agentdeck-protocol/src/e2ee/mod.rs",
    symbol: "E2EE_FORMAT_VERSION",
    value: 1,
    declaration: "pub const E2EE_FORMAT_VERSION: u16 = 1;",
    schemaPath: "protocol/agentdeck/e2ee-v1.schema.json",
    schemaCommand: "e2ee-schema",
    rust: ["agentdeck-protocol/src/e2ee/tbs.rs"],
    swift: ["Sources/AgentDeckRelayClient/Crypto/CanonicalCodec.swift"],
    fixtures: ["protocol/agentdeck/crypto-vectors-v1.json"],
  },
  localIpc: {
    versionPath: "agentdeck-protocol/src/lib.rs",
    symbol: "PROTOCOL_VERSION",
    value: 2,
    declaration: "pub const PROTOCOL_VERSION: u32 = 2;",
    schemaPath: "protocol/agentdeck/agentdeck-protocol.schema.json",
    schemaCommand: "schema",
    rust: ["agentdeck-protocol/src/lib.rs", "agentdeck-protocol/src/trunk.rs"],
    swift: ["Sources/AgentDeckCore/Protocol/V2Types.swift"],
    fixtures: [],
  },
  relay: {
    versionPath: "agentdeck-protocol/src/relay_v2/mod.rs",
    symbol: "RELAY_PROTOCOL_VERSION",
    value: 2,
    declaration: "pub const RELAY_PROTOCOL_VERSION: u16 = 2;",
    schemaPath: "protocol/agentdeck/relay-v2.schema.json",
    schemaCommand: "relay-schema",
    rust: ["agentdeck-protocol/src/relay_v2/codec.rs"],
    swift: ["Sources/AgentDeckRelayClient/Wire/RelayV2Types.swift"],
    fixtures: ["protocol/agentdeck/fixtures/relay-v2-wire-vectors.json"],
  },
  runtime: {
    versionPath: "agentdeck-protocol/src/runtime/mod.rs",
    symbol: "RUNTIME_PROTOCOL_VERSION",
    value: 5,
    declaration: "pub const RUNTIME_PROTOCOL_VERSION: u16 = 5;",
    schemaPath: "protocol/agentdeck/runtime-protocol.schema.json",
    schemaCommand: "runtime-schema",
    rust: ["agentdeck-protocol/src/runtime/envelope.rs"],
    swift: ["Sources/AgentDeckCore/Protocol/RuntimeV2WireCodec.swift"],
    fixtures: ["protocol/agentdeck/fixtures/runtime-v5-wire.jsonl"],
  },
};

exactKeys(manifest.axes, Object.keys(anchors), "manifest.axes");
const ownedSourcePaths = new Map();
for (const [axisName, anchor] of Object.entries(anchors)) {
  const axis = manifest.axes[axisName];
  exactKeys(axis, ["version", "rust", "swift", "schema", "fixtures", "schemaCommand"], `axes.${axisName}`);
  exactKeys(axis.version, ["path", "symbol", "value", "declaration"], `axes.${axisName}.version`);
  if (axis.version.path !== anchor.versionPath || axis.version.symbol !== anchor.symbol) {
    fail(`axes.${axisName}.version owner was rebound`);
  }
  if (axis.version.value !== anchor.value || axis.version.declaration !== anchor.declaration) {
    fail(`axes.${axisName} version is not frozen at ${anchor.value}`);
  }
  const versionSource = readFileSync(regularFile(axis.version.path, `${axisName} version`), "utf8");
  const declarationCount = versionSource
    .split(/\r?\n/)
    .filter((line) => line.trim() === axis.version.declaration).length;
  if (declarationCount !== 1) {
    fail(`axes.${axisName} version declaration drifted`);
  }

  validateGroup(axis.rust, `axes.${axisName}.rust`);
  validateGroup(axis.swift, `axes.${axisName}.swift`);
  validateGroup(axis.fixtures, `axes.${axisName}.fixtures`);
  for (const groupName of ["rust", "swift", "fixtures"]) {
    for (const path of axis[groupName].paths) {
      const previous = ownedSourcePaths.get(path);
      if (previous) fail(`${path} has multiple owners: ${previous}, ${axisName}.${groupName}`);
      ownedSourcePaths.set(path, `${axisName}.${groupName}`);
    }
  }
  for (const required of anchor.rust) {
    if (!axis.rust.paths.includes(required)) fail(`axes.${axisName}.rust missing ${required}`);
  }
  for (const required of anchor.swift) {
    if (!axis.swift.paths.includes(required)) fail(`axes.${axisName}.swift missing ${required}`);
  }
  for (const required of anchor.fixtures) {
    if (!axis.fixtures.paths.includes(required)) fail(`axes.${axisName}.fixtures missing ${required}`);
  }

  exactKeys(axis.schema, ["path", "sha256"], `axes.${axisName}.schema`);
  if (axis.schema.path !== anchor.schemaPath || axis.schemaCommand !== anchor.schemaCommand) {
    fail(`axes.${axisName} schema owner or command was rebound`);
  }
  validateHash(axis.schema.sha256, `axes.${axisName}.schema.sha256`);
  const schemaBytes = readFileSync(regularFile(axis.schema.path, `${axisName} schema`));
  const schemaHash = sha256(schemaBytes);
  if (schemaHash !== axis.schema.sha256) {
    fail(`axes.${axisName}.schema content drift: expected ${axis.schema.sha256}; got ${schemaHash}`);
  }

  const generated = Bun.spawnSync({
    cmd: [
      "cargo", "run", "-q", "-p", "agentdeck-cli", "--locked", "--",
      "protocol", axis.schemaCommand,
    ],
    cwd: root,
    env: process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (generated.exitCode !== 0) {
    const stderr = Buffer.from(generated.stderr).toString("utf8").trim();
    fail(`axes.${axisName} schema generator failed: ${stderr}`);
  }
  if (!Buffer.from(generated.stdout).equals(schemaBytes)) {
    fail(`axes.${axisName} generated schema bytes differ from ${axis.schema.path}`);
  }
}

for (const inventoryRoot of manifest.sourceInventoryRoots) {
  for (const file of regularFilesRecursively(directory(inventoryRoot, "source inventory root"))) {
    const path = relative(root, file);
    if (!ownedSourcePaths.has(path)) fail(`unowned protocol source: ${path}`);
  }
}

exactKeys(manifest.boundaries, ["packageManifest", "sessionSourceRoot", "ui"], "boundaries");
if (manifest.boundaries.packageManifest !== "Package.swift") {
  fail("boundaries.packageManifest must remain Package.swift");
}
if (manifest.boundaries.sessionSourceRoot !== "Sources/AgentDeckSessionSource") {
  fail("boundaries.sessionSourceRoot was rebound");
}
const packageSource = readFileSync(regularFile(manifest.boundaries.packageManifest, "Package.swift"), "utf8");
const targetMatch = packageSource.match(
  /\.target\(\s*name:\s*"AgentDeckSessionSource",\s*dependencies:\s*\[([\s\S]*?)\],\s*path:\s*"Sources\/AgentDeckSessionSource"\s*\)/
);
const normalizedSessionSourceDependencies = targetMatch ? targetMatch[1].replace(/\s+/g, "") : "";
if (!targetMatch || normalizedSessionSourceDependencies !== '.target(name:"AgentDeckCore")') {
  fail("AgentDeckSessionSource package dependency must remain Core-only");
}

const canonicalPatterns = [
  { id: "e2ee-wire", regex: "\\b(?:E2EE|OuterContextV1|SealedPayloadKind|SignedSealedBlobWireV1)\\b" },
  { id: "relay-wire", regex: "\\bRelayV2[A-Za-z0-9_]*\\b" },
  { id: "runtime-wire", regex: "\\bRuntime(?:Request|Reply|Envelope|StreamItem|TransferCarrier|WireCodec)V?[0-9]*\\b" },
];
const requiredUIRoots = [
  "Sources/AgentDeck/agent",
  "Sources/AgentDeck/capability",
  "Sources/AgentDeck/common",
  "Sources/AgentDeck/session",
];
const requiredSuffixes = [
  "Badge.swift", "Chrome.swift", "Controller.swift", "Dialog.swift", "Form.swift",
  "Panel.swift", "Picker.swift", "Presentation.swift", "RowFactory.swift", "View.swift",
  "ViewController.swift",
].sort();

const ui = manifest.boundaries.ui;
exactKeys(
  ui,
  ["sourceRoot", "roots", "rootFileSuffixes", "forbiddenImports", "forbiddenWirePatterns"],
  "boundaries.ui"
);
if (ui.sourceRoot !== "Sources/AgentDeck") fail("boundaries.ui.sourceRoot was rebound");
if (JSON.stringify(ui.roots) !== JSON.stringify([...ui.roots].sort())) {
  fail("boundaries.ui.roots must be sorted");
}
for (const required of requiredUIRoots) {
  if (!ui.roots.includes(required)) fail(`boundaries.ui.roots missing ${required}`);
}
if (JSON.stringify([...ui.rootFileSuffixes].sort()) !== JSON.stringify(requiredSuffixes)) {
  fail("boundaries.ui.rootFileSuffixes drifted");
}
if (JSON.stringify(ui.forbiddenImports) !== JSON.stringify(["AgentDeckRelayClient"])) {
  fail("boundaries.ui.forbiddenImports drifted");
}
if (JSON.stringify(ui.forbiddenWirePatterns) !== JSON.stringify(canonicalPatterns)) {
  fail("boundaries.ui.forbiddenWirePatterns drifted");
}

function swiftFilesRecursively(rootPath) {
  const result = [];
  for (const entry of readdirSync(rootPath, { withFileTypes: true })) {
    const absolute = join(rootPath, entry.name);
    if (entry.isSymbolicLink()) fail(`source boundary contains symlink: ${absolute}`);
    if (entry.isDirectory()) result.push(...swiftFilesRecursively(absolute));
    else if (entry.isFile() && entry.name.endsWith(".swift")) result.push(absolute);
  }
  return result;
}

const boundaryFiles = new Set();
for (const rootPath of ui.roots) {
  for (const file of swiftFilesRecursively(directory(rootPath, "UI root"))) boundaryFiles.add(file);
}
const uiSourceRoot = directory(ui.sourceRoot, "UI source root");
for (const file of swiftFilesRecursively(uiSourceRoot)) {
  if (ui.rootFileSuffixes.some((suffix) => file.endsWith(suffix))) boundaryFiles.add(file);
}
for (const file of swiftFilesRecursively(directory(manifest.boundaries.sessionSourceRoot, "SessionSource root"))) {
  boundaryFiles.add(file);
}

const patterns = canonicalPatterns.map(({ id, regex }) => ({ id, regex: new RegExp(regex) }));
for (const file of [...boundaryFiles].sort()) {
  const source = readFileSync(file, "utf8");
  for (const forbiddenImport of ui.forbiddenImports) {
    const importPattern = new RegExp(`^\\s*import\\s+${forbiddenImport}\\s*$`, "m");
    if (importPattern.test(source)) {
      fail(`${relative(root, file)} imports forbidden wire module ${forbiddenImport}`);
    }
  }
  for (const pattern of patterns) {
    if (pattern.regex.test(source)) {
      fail(`${relative(root, file)} contains forbidden ${pattern.id} type`);
    }
  }
}

console.log("verify-agentdeck-protocol-ownership: ok");
JS
