import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";

test("W2a real browser pairing reaches durable terminal", async ({ page }) => {
  test.setTimeout(150_000);
  const invitePath = process.env.AGENTDECK_W2_INVITE_PATH;
  if (invitePath === undefined) {
    throw new Error("W2a invite path is missing");
  }
  const invite = (await readFile(invitePath, "utf8")).trim();
  const consoleErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push(message.text());
    }
  });

  await page.goto("/");
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.ready)).toBe("true");
  const result = await page.evaluate(
    async (encodedInvite) => globalThis.relayTestApi.runW2Pairing(encodedInvite),
    invite,
  );

  expect(result.preConfirmNetworkLocked).toBe(true);
  expect(result.preview.machineDisplayName).toBe("P5.7 Swift dual-scope host");
  expect(result.preview.machineRootFingerprint).toMatch(/^sha256:(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/u);
  expect(result.failureCode, JSON.stringify(result)).toBeNull();
  expect(result.pairing).toMatchObject({
    fingerprintConfirmed: true,
    authenticated: true,
    pendingObserved: true,
    responseVerified: true,
    receiptSent: true,
    routeAcceptedObserved: true,
    paired: true,
    machineRoutePresent: true,
    deviceRoutePresent: true,
  });
  expect(result.binaryFramesSent).toBeGreaterThanOrEqual(4);
  await expect(page.locator("#w2-status")).toHaveText("W2a 真实配对通过");
  expect(consoleErrors).toEqual([]);
});

test("W2b real browser business flow closes prompt and approval", async ({ page }) => {
  test.setTimeout(180_000);
  const invitePath = process.env.AGENTDECK_W2_INVITE_PATH;
  if (invitePath === undefined) {
    throw new Error("W2b invite path is missing");
  }
  const invite = (await readFile(invitePath, "utf8")).trim();
  const consoleErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push(message.text());
    }
  });

  await page.goto("/");
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.ready)).toBe("true");
  const result = await page.evaluate(
    async (encodedInvite) => globalThis.relayTestApi.runW2Business(encodedInvite),
    invite,
  );

  expect(result.preConfirmNetworkLocked).toBe(true);
  expect(result.failureCode, JSON.stringify(result)).toBeNull();
  expect(result.pairing.paired).toBe(true);
  expect(result.pairing.receiptSent).toBe(true);
  expect(result.business).toMatchObject({
    principalAuthenticated: true,
    catalogRouteAccepted: true,
    catalogEntryCount: 1,
    conversationTitle: "R4.3 synthetic Codex",
    catalogSubscriptionActive: true,
    businessFenceCount: expect.any(Number),
    conversationRouteAccepted: true,
    conversationOpen: true,
    relaySubscriptionActive: true,
    promptRouteAccepted: true,
    promptAccepted: true,
    assistantObserved: true,
    approvalPending: true,
    approvalSummaryMatched: true,
    approvalRouteAccepted: true,
    approvalReceiptApplied: true,
    approvalEventApplied: true,
    commandCompleted: true,
  });
  expect(result.business?.outerAckCount).toBeGreaterThanOrEqual(7);
  expect(result.pairingBinaryFramesSent).toBeGreaterThanOrEqual(4);
  expect(result.businessBinaryFramesSent).toBeGreaterThanOrEqual(10);
  await expect(page.locator("#w2-status")).toHaveText("W2b 真实业务闭环通过");
  const visibleText = await page.locator("html").innerText();
  expect(visibleText).not.toContain("web-w2b-prompt-7fb7f299");
  expect(visibleText).not.toContain("synthetic Codex response");
  expect(visibleText).not.toContain("synthetic codex approval");
  expect(consoleErrors).toEqual([]);
});
