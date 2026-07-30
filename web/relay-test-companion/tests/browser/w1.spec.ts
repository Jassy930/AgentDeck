import { expect, test } from "@playwright/test";

test("W1 harness case", async ({ page }) => {
  const caseName = process.env.AGENTDECK_W1_CASE as W1TransportCase | undefined;
  const origin = process.env.AGENTDECK_W1_WSS_ORIGIN;
  const relayServerId = process.env.AGENTDECK_W1_RELAY_SERVER_ID_HEX;
  if (caseName === undefined || origin === undefined || relayServerId === undefined) {
    throw new Error("W1 harness environment missing");
  }

  const consoleErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push(message.text());
    }
  });
  await page.goto("/");
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.ready)).toBe("true");
  const result = await page.evaluate(
    async (input) =>
      globalThis.relayTestApi.runW1Transport(
        input.origin,
        input.relayServerId,
        input.caseName,
      ),
    { origin, relayServerId, caseName },
  );

  expect(result.caseName).toBe(caseName);
  expect(result.generation).toBeGreaterThan(0);
  const expected: Readonly<
    Record<W1TransportCase, Pick<W1TransportEvidence, "authenticated" | "sentinelAccepted" | "failureCode">>
  > = {
    positive: { authenticated: true, sentinelAccepted: true, failureCode: null },
    wrongServer: {
      authenticated: false,
      sentinelAccepted: false,
      failureCode: "web.remote.server_identity_mismatch",
    },
    tamperChallenge: {
      authenticated: false,
      sentinelAccepted: false,
      failureCode: "web.remote.handshake_rejected",
    },
    tamperSignature: {
      authenticated: false,
      sentinelAccepted: false,
      failureCode: "web.remote.handshake_rejected",
    },
    replayAuthenticate: {
      authenticated: true,
      sentinelAccepted: false,
      failureCode: "web.remote.replay_rejected",
    },
    textFrame: {
      authenticated: false,
      sentinelAccepted: false,
      failureCode: "web.remote.text_frame_rejected",
    },
    oversizeFrame: {
      authenticated: false,
      sentinelAccepted: false,
      failureCode: "web.remote.frame_too_large",
    },
    disconnect: {
      authenticated: false,
      sentinelAccepted: false,
      failureCode: "web.remote.disconnected",
    },
    unavailable: {
      authenticated: false,
      sentinelAccepted: false,
      failureCode: "web.remote.connect_failed",
    },
  };
  expect(result).toMatchObject(expected[caseName]);
  if (caseName === "positive") {
    await expect(page.locator("#w1-status")).toHaveText("W1 真实 Relay 通过");
    expect(consoleErrors).toEqual([]);
  }
  expect(consoleErrors.join("\n")).not.toContain("agentdeck-w1-sentinel");
});
