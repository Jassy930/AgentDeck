import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const webRoot = resolve(import.meta.dirname, "../..");
const repositoryRoot = resolve(webRoot, "../..");

async function runtimeFixture(): Promise<Uint8Array> {
  const source = await readFile(
    resolve(repositoryRoot, "protocol/agentdeck/fixtures/runtime-v5-wire.jsonl"),
    "utf8",
  );
  const entry = source
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as { case: string; value: unknown })
    .find((candidate) => candidate.case === "requestMachineRemoteStatus");
  if (entry === undefined) {
    throw new Error("Runtime v5 fixture missing");
  }
  return new TextEncoder().encode(JSON.stringify(entry.value));
}

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.ready)).toBe("true");
});

test("W0 WASM 与 Rust 共享 Relay/Runtime/crypto 契约", async ({ page }) => {
  const vectors = JSON.parse(
    await readFile(resolve(repositoryRoot, "protocol/agentdeck/crypto-vectors-v1.json"), "utf8"),
  ) as Record<string, Record<string, string>>;

  const snapshot = await page.evaluate(() => globalThis.relayTestApi.contractSnapshot());
  expect(snapshot.relayHelloHex).toBe("4144525632000200000002");
  expect(snapshot.sha256Hex).toBe(vectors.sha256?.digestHex);
  expect(snapshot.tbsHex).toBe(vectors.tbs_canonical?.encodedHex);
  expect(snapshot.ed25519PublicKeyHex).toBe(vectors.ed25519?.publicKeyHex);
  expect(snapshot.ed25519SignatureHex).toBe(vectors.ed25519?.signatureHex);
  expect(snapshot.aeadNonceHex).toBe(vectors.chacha20poly1305?.nonceHex);
  expect(snapshot.aeadCiphertextHex).toBe(vectors.chacha20poly1305?.ciphertextHex);
  expect(snapshot.hpkeInfoHex).toBe(vectors.hpke_base_kat?.infoHex);
  expect(snapshot.hpkeRecipientPublicHex).toBe(vectors.hpke_base_kat?.recipientPubHex);
  expect(snapshot.hpkeEncHex).toBe(vectors.hpke_base_kat?.encHex);
  expect(snapshot.hpkeCiphertextHex).toBe(vectors.hpke_base_kat?.ciphertextHex);

  const hello = await page.evaluate(() => globalThis.relayTestApi.relayHello());
  const badMagic = hello.slice();
  badMagic[0] = (badMagic[0] ?? 0) ^ 0xff;
  const badVersion = hello.slice();
  badVersion[6] = 3;
  const unknownKind = hello.slice();
  unknownKind[7] = 0xff;
  unknownKind[8] = 0xff;
  await expect(page.evaluate((value) => globalThis.relayTestApi.relayFrameRejected(value), badMagic)).resolves.toBe(true);
  await expect(page.evaluate((value) => globalThis.relayTestApi.relayFrameRejected(value), badVersion)).resolves.toBe(true);
  await expect(page.evaluate((value) => globalThis.relayTestApi.relayFrameRejected(value), unknownKind)).resolves.toBe(true);
  await expect(page.evaluate((value) => globalThis.relayTestApi.relayFrameRejected(value), hello.slice(0, -1))).resolves.toBe(true);

  const runtime = await runtimeFixture();
  const roundtrip = await page.evaluate(
    (value) => globalThis.relayTestApi.runtimeRoundtrip(value),
    Array.from(runtime),
  );
  expect(JSON.parse(new TextDecoder().decode(Uint8Array.from(roundtrip)))).toEqual(
    JSON.parse(new TextDecoder().decode(runtime)),
  );
  const invalidRuntime = JSON.parse(new TextDecoder().decode(runtime)) as Record<string, unknown>;
  invalidRuntime.unexpected = true;
  const invalidRuntimeBytes = Array.from(new TextEncoder().encode(JSON.stringify(invalidRuntime)));
  await expect(
    page.evaluate((value) => globalThis.relayTestApi.runtimeRejected(value), invalidRuntimeBytes),
  ).resolves.toBe(true);

  const negatives = await page.evaluate(() => globalThis.relayTestApi.negativeSnapshot());
  expect(Object.values(negatives)).not.toContain(false);
  await expect(page.evaluate(() => globalThis.relayTestApi.cryptoTamperRejected())).resolves.toBe(true);
});

test("W0 IndexedDB KEK、CAS 与事务回滚闭环", async ({ page }) => {
  const profile = "w0-storage";
  await page.evaluate((id) => globalThis.relayTestApi.deleteProfile(id), profile);
  const kek = await page.evaluate(
    (id) => globalThis.relayTestApi.createAndProveNonExtractableKek(id),
    profile,
  );
  expect(kek).toEqual({
    algorithm: "AES-GCM",
    extractable: false,
    roundtrip: true,
    exportRejected: true,
  });

  await page.evaluate((id) => globalThis.relayTestApi.initializeState(id, "previous"), profile);
  const rolledBack = await page.evaluate(
    (id) => globalThis.relayTestApi.commitExactRevision(id, 0, 1, "aborted-next", true),
    profile,
  );
  expect(rolledBack).toMatchObject({ revision: 0, payload: "previous" });

  const committed = await page.evaluate(
    (id) => globalThis.relayTestApi.commitExactRevision(id, 0, 1, "exact-next"),
    profile,
  );
  expect(committed).toMatchObject({ revision: 1, payload: "exact-next" });

  await expect(
    page.evaluate((id) => globalThis.relayTestApi.commitExactRevision(id, 0, 1, "sibling"), profile),
  ).rejects.toThrow("web.remote.storage.revisionConflict");
  await expect(
    page.evaluate((id) => globalThis.relayTestApi.commitExactRevision(id, 1, 3, "skipped"), profile),
  ).rejects.toThrow("web.remote.storage.nonExactNextRevision");

  const readback = await page.evaluate((id) => globalThis.relayTestApi.readState(id), profile);
  expect(readback).toMatchObject({ revision: 1, payload: "exact-next" });
  await page.evaluate((id) => globalThis.relayTestApi.deleteProfile(id), profile);
  await expect(page.evaluate((id) => globalThis.relayTestApi.readState(id), profile)).resolves.toBeNull();
  await page.evaluate((id) => globalThis.relayTestApi.deleteProfile(id), profile);
});

test("W0 Web Locks 拒绝第二 tab 并可交接新 generation", async ({ page, context }) => {
  const profile = "w0-single-writer";
  await expect(page.evaluate((id) => globalThis.relayTestApi.acquireWriter(id), profile)).resolves.toBe(true);

  const second = await context.newPage();
  await second.goto("/");
  await expect.poll(() => second.evaluate(() => document.documentElement.dataset.ready)).toBe("true");
  await expect(second.evaluate((id) => globalThis.relayTestApi.acquireWriter(id), profile)).resolves.toBe(false);

  await page.evaluate((id) => globalThis.relayTestApi.releaseWriter(id), profile);
  await expect(second.evaluate((id) => globalThis.relayTestApi.acquireWriter(id), profile)).resolves.toBe(true);
  await second.evaluate((id) => globalThis.relayTestApi.releaseWriter(id), profile);
  await second.close();
});

test("W0 页面自检可见且 CSP 收紧", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push(message.text());
    }
  });
  await page.reload();
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.ready)).toBe("true");

  const response = await page.request.get("/");
  const csp = response.headers()["content-security-policy"];
  expect(csp).toContain("default-src 'none'");
  expect(csp).toContain("connect-src 'self'");
  expect(csp).not.toContain("'unsafe-inline'");
  await expect(page.request.post("/").then((result) => result.status())).resolves.toBe(405);

  await page.getByRole("button", { name: "运行 W0 自检" }).click();
  await expect(page.locator("#w0-status")).toHaveAttribute("data-state", "passed");
  await expect(page.locator("#evidence")).toContainText("Relay Hello: 4144525632000200000002");
  expect(consoleErrors).toEqual([]);
});
