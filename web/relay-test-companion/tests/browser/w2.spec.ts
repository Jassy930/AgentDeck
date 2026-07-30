import { readFile, writeFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";

test("W2.7 WASM negative admission matrix is zero-mutation", async ({ page }) => {
  await page.goto("/");
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.ready)).toBe("true");

  const snapshot = await page.evaluate(() => globalThis.relayTestApi.w2NegativeSnapshot());
  expect(snapshot).toEqual({
    approvalLoserRecognizedApplied: true,
    approvalLoserZeroClaimMutation: true,
    stalePublishRejected: true,
    skippedPublishRejected: true,
    rejectedPublishCursorUnchanged: true,
    replyNonceReplayRejected: true,
    replyCounterSetUnchanged: true,
    streamNonceReuseRejected: true,
    streamCounterSetUnchanged: true,
    uncommittedReservationRejected: true,
    reservationOverflowRejected: true,
    rejectedReservationCounterUnchanged: true,
  });
});

test("W3.2 statePending sibling is durably quarantined without network", async ({ page }) => {
  const profileId = "w3-state-fork";
  await page.goto("/");
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.ready)).toBe("true");
  const result = await page.evaluate(
    async (profile) => globalThis.relayTestApi.runW3StateForkProbe(profile),
    profileId,
  );
  expect(result.failureCode, JSON.stringify(result)).toBeNull();
  expect(result).toMatchObject({
    faultInjected: true,
    rejectionCode: "web.remote.storage.state_fork_quarantined",
    durableRejectionCode: "web.remote.storage.state_quarantined",
    binaryFramesSent: 0,
    storage: {
      pairedRevision: 1,
      guardPhase: "quarantined",
      quarantineReason: "stateFork",
      stagedCiphertextBytes: 0,
    },
  });
  await page.evaluate(async (profile) => globalThis.relayTestApi.deleteProfile(profile), profileId);
  expect(
    await page.evaluate(async (profile) => globalThis.relayTestApi.readState(profile), profileId),
  ).toBeNull();
});

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

test("W2c durable reload reconnect backfill and revoke closes", async ({ page, context }) => {
  test.setTimeout(240_000);
  const invitePath = process.env.AGENTDECK_W2_INVITE_PATH;
  const coordinationDir = process.env.AGENTDECK_W2_COORDINATION_DIR;
  const profileId = process.env.AGENTDECK_W2_PROFILE_ID;
  const crashCut = process.env.AGENTDECK_W3_CRASH_CUT as W3CrashCut | undefined;
  const stateCut = process.env.AGENTDECK_W3_STATE_CUT as W3StateCut | undefined;
  const writerContention = process.env.AGENTDECK_W3_CONTENTION === "1";
  if (invitePath === undefined || coordinationDir === undefined || profileId === undefined) {
    throw new Error("W2c runner contract is missing");
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
  if (
    Number(crashCut !== undefined) + Number(stateCut !== undefined) + Number(writerContention) >
    1
  ) {
    throw new Error("W3 runner selected multiple fault families");
  }
  const started =
    stateCut === undefined
      ? await page.evaluate(
          async ({ encodedInvite, profile }) =>
            globalThis.relayTestApi.runW2DurableStart(encodedInvite, profile),
          { encodedInvite: invite, profile: profileId },
        )
      : await page.evaluate(
          async ({ encodedInvite, profile, cut }) =>
            globalThis.relayTestApi.runW3StateCrashStart(encodedInvite, profile, cut),
          { encodedInvite: invite, profile: profileId, cut: stateCut },
        );
  expect(started.failureCode, JSON.stringify(started)).toBeNull();
  if (stateCut === undefined) {
    expect("revision" in started ? started.revision : null).toBe(1);
  } else {
    expect(started).toMatchObject({
      cut: stateCut,
      revisionBefore: 0,
      faultInjected: true,
      recoveryBinaryFramesSent: 0,
    });
    const expectedPairedRevision = stateCut === "stateGuardPendingDurable" ? 0 : 1;
    const expectedGuardPhase = stateCut === "guardStableDurable" ? "stable" : "statePending";
    expect("storage" in started ? started.storage : null).toMatchObject({
      pairedRevision: expectedPairedRevision,
      guardPhase: expectedGuardPhase,
      guardRevision: stateCut === "guardStableDurable" ? 1 : null,
      pendingPreviousRevision: stateCut === "guardStableDurable" ? null : 0,
      pendingNextRevision: stateCut === "guardStableDurable" ? null : 1,
    });
  }
  expect(started.business).toMatchObject({
    durablePromoted: true,
    commandCompleted: true,
    approvalReceiptApplied: true,
    approvalEventApplied: true,
    counterReservationStart: 0,
    counterReservationEnd: 256,
  });
  if (stateCut === undefined) {
    expect(started.storage).toMatchObject({
      pairedPresent: true,
      kekPresent: true,
      revokedPresent: false,
      revision: 1,
    });
    expect("ciphertextBytes" in started.storage ? started.storage.ciphertextBytes : 0).toBeGreaterThan(
      16,
    );
  }
  if (writerContention) {
    expect(
      await page.evaluate((profile) => globalThis.relayTestApi.writerGenerationSnapshot(profile), profileId),
    ).toMatchObject({ acquired: true, relinquished: false, invalidatedByPeer: false });

    const second = await context.newPage();
    await second.goto("/");
    await expect.poll(() => second.evaluate(() => document.documentElement.dataset.ready)).toBe("true");
    await expect(
      second.evaluate((profile) => globalThis.relayTestApi.acquireWriterGeneration(profile), profileId),
    ).resolves.toBe(false);
    const lockedProbe = await second.evaluate(
      (profile) => globalThis.relayTestApi.runW3LateGenerationProbe(profile),
      profileId,
    );
    expect(lockedProbe.failureCode, JSON.stringify(lockedProbe)).toBeNull();
    expect(lockedProbe).toMatchObject({
      rejectionCode: "web.remote.writer_generation_missing",
      binaryFramesSent: 0,
      canonicalMutationCount: 0,
      pairedRevisionBefore: 1,
      pairedRevisionAfter: 1,
      guardPhaseBefore: "stable",
      guardPhaseAfter: "stable",
    });

    await page.evaluate(
      (profile) => globalThis.relayTestApi.relinquishWriterGeneration(profile),
      profileId,
    );
    await expect(
      second.evaluate((profile) => globalThis.relayTestApi.acquireWriterGeneration(profile), profileId),
    ).resolves.toBe(true);
    await expect
      .poll(() =>
        page.evaluate(
          (profile) => globalThis.relayTestApi.writerGenerationSnapshot(profile),
          profileId,
        ),
      )
      .toMatchObject({ relinquished: true, invalidatedByPeer: true });
    const staleProbe = await page.evaluate(
      (profile) => globalThis.relayTestApi.runW3LateGenerationProbe(profile),
      profileId,
    );
    expect(staleProbe.failureCode, JSON.stringify(staleProbe)).toBeNull();
    expect(staleProbe).toMatchObject({
      rejectionCode: "web.remote.generation_stale",
      binaryFramesSent: 0,
      canonicalMutationCount: 0,
      pairedRevisionBefore: 1,
      pairedRevisionAfter: 1,
      guardPhaseBefore: "stable",
      guardPhaseAfter: "stable",
    });
    await second.evaluate(
      (profile) => globalThis.relayTestApi.releaseWriterGeneration(profile),
      profileId,
    );
    await second.close();
  }
  await writeFile(`${coordinationDir}/business.ready`, "ready\n", { flag: "wx", mode: 0o600 });

  await expect
    .poll(
      async () => {
        try {
          return JSON.parse(await readFile(`${coordinationDir}/restart.begin`, "utf8")) as Record<
            string,
            unknown
          >;
        } catch {
          return null;
        }
      },
      { timeout: 90_000 },
    )
    .not.toBeNull();

  await page.reload();
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.ready)).toBe("true");
  if (crashCut !== undefined) {
    const crashed = await page.evaluate(
      async ({ profile, cut }) => globalThis.relayTestApi.runW3ReservationCrash(profile, cut),
      { profile: profileId, cut: crashCut },
    );
    expect(crashed.failureCode, JSON.stringify(crashed)).toBeNull();
    expect(crashed).toMatchObject({
      cut: crashCut,
      revisionBefore: 1,
      faultInjected: true,
      binaryFramesSent: 0,
    });
    const expectedPairedRevision = crashCut === "guardPendingDurable" ? 1 : 2;
    const expectedGuardPhase = crashCut === "guardStableDurable" ? "stable" : "pending";
    expect(crashed.storage).toMatchObject({
      pairedRevision: expectedPairedRevision,
      guardPhase: expectedGuardPhase,
      guardRevision: crashCut === "guardStableDurable" ? 2 : null,
      pendingPreviousRevision: crashCut === "guardStableDurable" ? null : 1,
      pendingNextRevision: crashCut === "guardStableDurable" ? null : 2,
    });
    if (crashCut === "guardStableDurable") {
      expect(crashed.storage.stagedCiphertextBytes).toBe(0);
    } else {
      expect(crashed.storage.stagedCiphertextBytes).toBeGreaterThan(16);
    }
    await page.reload();
    await expect.poll(() => page.evaluate(() => document.documentElement.dataset.ready)).toBe(
      "true",
    );
  }
  const recovered = await page.evaluate(
    async (profile) => globalThis.relayTestApi.runW2DurableRecover(profile),
    profileId,
  );
  expect(recovered.failureCode, JSON.stringify(recovered)).toBeNull();
  expect(recovered.revision).toBe(crashCut === undefined ? 3 : 4);
  expect(recovered.preActivationNetworkLocked).toBe(true);
  expect(recovered.reloadStatus).toBe("revoked");
  expect(recovered.business).toMatchObject({
    durablePromoted: true,
    durableRestored: true,
    reconnectAuthenticated: true,
    counterReservationStart: crashCut === undefined ? 256 : 512,
    counterReservationEnd: crashCut === undefined ? 512 : 768,
    restartMarkerObserved: true,
    revocationReceiptCommitted: true,
    revocationTerminalVerified: true,
    commandCompleted: true,
    approvalReceiptApplied: true,
    approvalEventApplied: true,
  });
  expect(recovered.business?.recoveryCatalogBackfillCount).toBeGreaterThanOrEqual(1);
  expect(recovered.reservationRecovery).toBe(
    stateCut === "stateGuardPendingDurable"
      ? "statePendingPreviousRetried"
      : stateCut === "stateDurable"
        ? "statePendingNextFinalized"
        : stateCut === "guardStableDurable"
          ? "stableExact"
          : crashCut === undefined
            ? "stableExact"
      : crashCut === "guardPendingDurable"
        ? "pendingPreviousFinalized"
        : crashCut === "stateDurable"
          ? "pendingNextFinalized"
          : "stableExact",
  );
  expect(recovered.storage).toEqual({
    pairedPresent: false,
    kekPresent: false,
    revokedPresent: true,
    revision: crashCut === undefined ? 3 : 4,
    ciphertextBytes: 0,
  });
  expect(recovered.binaryFramesSent).toBeGreaterThanOrEqual(8);
  await expect(page.locator("#w2-status")).toHaveText("W2c reload/reconnect/revoke 闭环通过");
  await expect
    .poll(
      async () => {
        try {
          return JSON.parse(await readFile(`${coordinationDir}/restart.done`, "utf8")) as Record<
            string,
            unknown
          >;
        } catch {
          return null;
        }
      },
      { timeout: 30_000 },
    )
    .not.toBeNull();
  const restartRecord = JSON.parse(
    await readFile(`${coordinationDir}/restart.done`, "utf8"),
  ) as Record<string, unknown>;
  expect(restartRecord).toMatchObject({
    daemonGeneration: 2,
    restartMarkerTitle: "R4.4 daemon restart marker",
    metadataEntryRevision: 1,
  });

  const rejectedReconnect = await page.evaluate(
    async (profile) => globalThis.relayTestApi.runW2DurableRecover(profile),
    profileId,
  );
  expect(rejectedReconnect.failureCode).toBe("web.remote.durable.revoked");
  expect(rejectedReconnect.binaryFramesSent).toBe(0);
  expect(rejectedReconnect.reloadStatus).toBe("revoked");
  const visibleText = await page.locator("html").innerText();
  expect(visibleText).not.toContain("web-w2b-prompt-7fb7f299");
  expect(visibleText).not.toContain("synthetic Codex response");
  expect(visibleText).not.toContain("synthetic codex approval");
  expect(visibleText).not.toContain("R4.4 daemon restart marker");
  expect(consoleErrors).toEqual([]);
});
