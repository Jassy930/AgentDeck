import { readdir, rmdir, unlink } from "node:fs/promises";
import { resolve } from "node:path";

const webRoot = resolve(import.meta.dir, "..");
const outputDirectory = resolve(webRoot, "test-results");
const child = Bun.spawn(["bunx", "playwright", "test", ...Bun.argv.slice(2)], {
  cwd: webRoot,
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
});
const exitCode = await child.exited;
if (exitCode !== 0) {
  process.exit(exitCode);
}
let entries: string[] = [];
try {
  entries = await readdir(outputDirectory);
} catch (error) {
  if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) {
    throw error;
  }
}

if (entries.length > 0 && !entries.every((entry) => entry === ".last-run.json")) {
  throw new Error(`web.remote.cleanup.unexpectedArtifacts:${entries.sort().join(",")}`);
}
if (entries.includes(".last-run.json")) {
  await unlink(resolve(outputDirectory, ".last-run.json"));
}
if (entries.length > 0 || (await Bun.file(outputDirectory).exists())) {
  await rmdir(outputDirectory);
}
