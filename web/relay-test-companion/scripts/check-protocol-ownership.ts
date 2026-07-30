import { readdir } from "node:fs/promises";
import { extname, resolve } from "node:path";

const sourceRoot = resolve(import.meta.dir, "../src");
const forbidden = [
  /\bRelayFrameBody\b/u,
  /\bRuntimeEnvelope\b/u,
  /\bToBeSignedV1\b/u,
  /\bhpke_(?:seal|open)\b/iu,
  /\bChaCha20Poly1305\b/u,
  /\bRELAY_FRAME_MAGIC\b/u,
  /\bRELAY_PROTOCOL_VERSION\b/u,
  /\bRUNTIME_PROTOCOL_VERSION\b/u,
  /\b(?:privateKey|private_key|recipientPrivate|recipientPriv|secretKey)\b/u,
  /crypto\.subtle\.importKey/u,
];

async function sourceFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) {
        return sourceFiles(path);
      }
      return extname(entry.name) === ".ts" ? [path] : [];
    }),
  );
  return nested.flat();
}

const violations: string[] = [];
for (const path of await sourceFiles(sourceRoot)) {
  const source = await Bun.file(path).text();
  for (const pattern of forbidden) {
    if (pattern.test(source)) {
      violations.push(`${path}: forbidden protocol/crypto owner pattern ${pattern.source}`);
    }
  }
}

if (violations.length > 0) {
  throw new Error(violations.join("\n"));
}

console.log("TypeScript protocol ownership check: PASS");
