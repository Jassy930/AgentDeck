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
  expect(result.failureCode).toBeNull();
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
