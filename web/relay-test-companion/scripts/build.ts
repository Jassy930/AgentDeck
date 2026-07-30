import { $ } from "bun";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(scriptDirectory, "..");
const repositoryRoot = resolve(webRoot, "../..");
const wasmOutput = resolve(webRoot, "generated/agentdeck-web-core");
const distribution = resolve(webRoot, "dist");

await $`bunx --bun wasm-pack build ${resolve(repositoryRoot, "agentdeck-web-core")} --target web --release --out-dir ${wasmOutput} --out-name agentdeck_web_core`;

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
