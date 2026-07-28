#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
verifier="$repo_root/scripts/verify-agentdeck-protocol-ownership.sh"
manifest="$repo_root/protocol/agentdeck/protocol-ownership.json"

if [[ ! -x "$verifier" ]]; then
  echo "FAIL: missing executable protocol ownership verifier: $verifier" >&2
  exit 1
fi
if [[ ! -f "$manifest" ]]; then
  echo "FAIL: missing protocol ownership manifest: $manifest" >&2
  exit 1
fi

expect_failure() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: $label unexpectedly passed" >&2
    exit 1
  fi
  echo "PASS: $label"
}

make_fixture() {
  local destination="$1"
  bun - "$repo_root" "$destination" <<'JS'
import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const [, , sourceRoot, destinationRoot] = process.argv;
const manifestPath = join(sourceRoot, "protocol/agentdeck/protocol-ownership.json");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

function copy(relativePath) {
  const source = join(sourceRoot, relativePath);
  const destination = join(destinationRoot, relativePath);
  mkdirSync(dirname(destination), { recursive: true });
  cpSync(source, destination, { recursive: true });
}

const paths = new Set([manifest.boundaries.packageManifest]);
copy("protocol/agentdeck/protocol-ownership.json");
for (const axis of Object.values(manifest.axes)) {
  paths.add(axis.version.path);
  for (const path of axis.rust.paths) paths.add(path);
  for (const path of axis.swift.paths) paths.add(path);
  paths.add(axis.schema.path);
  for (const path of axis.fixtures.paths) paths.add(path);
}
for (const path of paths) copy(path);
copy(manifest.boundaries.ui.sourceRoot);
copy(manifest.boundaries.sessionSourceRoot);

for (const axis of Object.values(manifest.axes)) {
  const generated = join(destinationRoot, "generated", `${axis.schemaCommand}.json`);
  mkdirSync(dirname(generated), { recursive: true });
  cpSync(join(sourceRoot, axis.schema.path), generated);
}

mkdirSync(join(destinationRoot, "bin"), { recursive: true });
writeFileSync(
  join(destinationRoot, "bin", "cargo"),
  `#!/usr/bin/env bash\nset -euo pipefail\nlast="\${!#}"\ncat "$AGENTDECK_OWNERSHIP_FIXTURE_ROOT/generated/$last.json"\n`,
  { mode: 0o755 },
);
JS
}

run_fixture() {
  local fixture_root="$1"
  PATH="$fixture_root/bin:$PATH" \
    AGENTDECK_OWNERSHIP_FIXTURE_ROOT="$fixture_root" \
    bash "$verifier" --root "$fixture_root"
}

bash "$verifier"
echo "PASS: repository ownership manifest"

fixture_base="$(mktemp -d /private/tmp/agentdeck-protocol-ownership.XXXXXX)"
trap 'find "$fixture_base" -depth -delete' EXIT

positive="$fixture_base/positive"
make_fixture "$positive"
run_fixture "$positive" >/dev/null
echo "PASS: isolated positive fixture"

version_fixture="$fixture_base/version"
make_fixture "$version_fixture"
bun - "$version_fixture" <<'JS'
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const root = process.argv[2];
const manifestPath = join(root, "protocol/agentdeck/protocol-ownership.json");
const sourcePath = join(root, "agentdeck-protocol/src/lib.rs");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const declaration = "pub const PROTOCOL_VERSION: u32 = 2;";
const changedDeclaration = "pub const PROTOCOL_VERSION: u32 = 99;";
writeFileSync(sourcePath, readFileSync(sourcePath, "utf8").replace(declaration, changedDeclaration));
manifest.axes.localIpc.version.value = 99;
manifest.axes.localIpc.version.declaration = changedDeclaration;
const digest = createHash("sha256");
for (const path of manifest.axes.localIpc.rust.paths) {
  const fileHash = createHash("sha256").update(readFileSync(join(root, path))).digest("hex");
  digest.update(`${path}\t${fileHash}\n`);
}
manifest.axes.localIpc.rust.contentSha256 = digest.digest("hex");
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
JS
expect_failure "coordinated version drift" run_fixture "$version_fixture"

mirror_fixture="$fixture_base/mirror"
make_fixture "$mirror_fixture"
bun - "$mirror_fixture/Sources/AgentDeckCore/Protocol/V2Types.swift" <<'JS'
import { appendFileSync } from "node:fs";
appendFileSync(process.argv[2], "\n// deterministic mirror drift\n");
JS
expect_failure "Swift mirror drift" run_fixture "$mirror_fixture"

inventory_fixture="$fixture_base/inventory"
make_fixture "$inventory_fixture"
bun - "$inventory_fixture/agentdeck-protocol/src/runtime/unowned.rs" <<'JS'
import { writeFileSync } from "node:fs";
writeFileSync(process.argv[2], "// unregistered protocol owner\n");
JS
expect_failure "unregistered protocol source" run_fixture "$inventory_fixture"

package_fixture="$fixture_base/package"
make_fixture "$package_fixture"
bun - "$package_fixture/Package.swift" <<'JS'
import { readFileSync, writeFileSync } from "node:fs";
const path = process.argv[2];
const source = readFileSync(path, "utf8").replace(
  'dependencies: [.target(name: "AgentDeckCore")],',
  'dependencies: [.target(name: "AgentDeckCore"), .target(name: "AgentDeckRelayClient")],',
);
writeFileSync(path, source);
JS
expect_failure "SessionSource wire dependency" run_fixture "$package_fixture"

ui_fixture="$fixture_base/ui"
make_fixture "$ui_fixture"
bun - "$ui_fixture/Sources/AgentDeck/session/AgentControlBar.swift" <<'JS'
import { appendFileSync } from "node:fs";
appendFileSync(process.argv[2], "\nprivate let forbiddenWireLeak: RuntimeRequestV2? = nil\n");
JS
expect_failure "UI wire dependency" run_fixture "$ui_fixture"

schema_fixture="$fixture_base/schema"
make_fixture "$schema_fixture"
bun - "$schema_fixture" <<'JS'
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const root = process.argv[2];
const manifestPath = join(root, "protocol/agentdeck/protocol-ownership.json");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const schemaPath = join(root, manifest.axes.runtime.schema.path);
const changed = Buffer.concat([readFileSync(schemaPath), Buffer.from("\n")]);
writeFileSync(schemaPath, changed);
manifest.axes.runtime.schema.sha256 = createHash("sha256").update(changed).digest("hex");
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
JS
expect_failure "generated schema parity drift" run_fixture "$schema_fixture"

echo "verify-agentdeck-protocol-ownership tests: PASS"
