import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(scriptDirectory, "..");
const repositoryRoot = resolve(webRoot, "../..");
const wasmOutput = resolve(webRoot, "generated/agentdeck-web-core");
const distribution = resolve(webRoot, "dist");
const requestedFeatures = process.env.AGENTDECK_WEB_CORE_FEATURES;
if (
  requestedFeatures !== undefined &&
  requestedFeatures !== "w1-test-fixture" &&
  requestedFeatures !== "w2-test-fixture"
) {
  throw new Error("web.remote.build.features_invalid");
}

const wasmCommand = [
  "bunx",
  "--bun",
  "wasm-pack",
  "build",
  resolve(repositoryRoot, "agentdeck-web-core"),
  "--target",
  "web",
  "--release",
  "--out-dir",
  wasmOutput,
  "--out-name",
  "agentdeck_web_core",
];
if (requestedFeatures !== undefined) {
  wasmCommand.push("--", "--features", requestedFeatures);
}
const wasmBuild = Bun.spawn(wasmCommand, {
  cwd: webRoot,
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
});
if ((await wasmBuild.exited) !== 0) {
  throw new Error("web.remote.build.wasm_failed");
}

const wasmGlue = await Bun.file(resolve(wasmOutput, "agentdeck_web_core.js")).text();
for (const forbiddenExport of [
  /export[^\n]*(?:private|secret)[A-Za-z_]*key/iu,
  /(?:root|link|data)[A-Za-z_]*seed/iu,
]) {
  if (forbiddenExport.test(wasmGlue)) {
    throw new Error("web.remote.build.secret_export");
  }
}

const result = await Bun.build({
  entrypoints: [resolve(webRoot, "src/main.ts")],
  outdir: distribution,
  target: "browser",
  format: "esm",
  sourcemap: "external",
});
if (!result.success) {
  for (const log of result.logs) {
    console.error(log);
  }
  throw new Error("web.remote.build.failed");
}

await Promise.all([
  Bun.write(resolve(distribution, "index.html"), Bun.file(resolve(webRoot, "static/index.html"))),
  Bun.write(resolve(distribution, "styles.css"), Bun.file(resolve(webRoot, "static/styles.css"))),
  Bun.write(
    resolve(distribution, "tokens.css"),
    Bun.file(resolve(repositoryRoot, "designs/agentdeck-design-system/generated/tokens.css")),
  ),
]);
