export type W2WasmSession = Readonly<{
  previewJson: () => string;
  confirm: (fingerprint: string, nowMs: bigint) => void;
  connectUrl: () => string;
  startHello: () => Uint8Array;
  startPairingHello: () => Uint8Array;
  acceptAuthenticated: (bytes: Uint8Array) => Uint8Array;
  acceptPairFrame: (bytes: Uint8Array, nowMs: bigint) => Uint8Array;
  paired: () => boolean;
  evidenceJson: () => string;
  businessConnectUrl: () => string;
  businessStartHello: () => Uint8Array;
  businessAcceptChallenge: (bytes: Uint8Array) => Uint8Array;
  businessAcceptAuthenticated: (bytes: Uint8Array) => void;
  businessStartCatalog: () => Uint8Array;
  businessStartConversation: () => Uint8Array;
  businessStartPrompt: () => Uint8Array;
  businessStartApproval: () => Uint8Array;
  businessAcceptFrame: (bytes: Uint8Array) => Uint8Array;
  businessEvidenceJson: () => string;
  free: () => void;
}>;

export type W2WasmSessionConstructor = new (
  encodedInvite: string,
  nowMs: bigint,
) => W2WasmSession;

const CONNECT_TIMEOUT_MS = 5_000;
const PAIRING_TIMEOUT_MS = 120_000;
const BUSINESS_TIMEOUT_MS = 120_000;
let nextGeneration = 0;
let activeGeneration: number | null = null;

function nowMs(): bigint {
  return BigInt(Date.now());
}

function withDeadline<T>(promise: Promise<T>, timeoutMs: number, code: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(code)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  });
}

function waitForOpen(socket: WebSocket, generation: number): Promise<void> {
  return withDeadline(
    new Promise<void>((resolve, reject) => {
      const opened = (): void => {
        cleanup();
        activeGeneration === generation
          ? resolve()
          : reject(new Error("web.remote.generation_stale"));
      };
      const failed = (): void => {
        cleanup();
        reject(new Error("web.remote.connect_failed"));
      };
      const closed = (): void => {
        cleanup();
        reject(new Error("web.remote.connection_closed"));
      };
      const cleanup = (): void => {
        socket.removeEventListener("open", opened);
        socket.removeEventListener("error", failed);
        socket.removeEventListener("close", closed);
      };
      socket.addEventListener("open", opened, { once: true });
      socket.addEventListener("error", failed, { once: true });
      socket.addEventListener("close", closed, { once: true });
    }),
    CONNECT_TIMEOUT_MS,
    "web.remote.connect_timeout",
  );
}

function receiveBinary(socket: WebSocket, generation: number): Promise<Uint8Array> {
  return new Promise<Uint8Array>((resolve, reject) => {
    const received = (event: MessageEvent<unknown>): void => {
      cleanup();
      if (activeGeneration !== generation) {
        reject(new Error("web.remote.generation_stale"));
      } else if (event.data instanceof ArrayBuffer) {
        resolve(new Uint8Array(event.data));
      } else {
        reject(new Error("web.remote.text_frame_rejected"));
      }
    };
    const failed = (): void => {
      cleanup();
      reject(new Error("web.remote.connection_failed"));
    };
    const closed = (): void => {
      cleanup();
      reject(new Error("web.remote.connection_closed"));
    };
    const cleanup = (): void => {
      socket.removeEventListener("message", received);
      socket.removeEventListener("error", failed);
      socket.removeEventListener("close", closed);
    };
    socket.addEventListener("message", received, { once: true });
    socket.addEventListener("error", failed, { once: true });
    socket.addEventListener("close", closed, { once: true });
  });
}

async function closeSocket(socket: WebSocket, reason: string): Promise<void> {
  if (socket.readyState === WebSocket.CLOSED) {
    return;
  }
  const closed = new Promise<void>((resolve) => {
    socket.addEventListener("close", () => resolve(), { once: true });
  });
  if (socket.readyState !== WebSocket.CLOSING) {
    socket.close(1000, reason);
  }
  await withDeadline(closed, 3_000, "web.remote.close_timeout").catch(() => undefined);
}

function failureCode(error: unknown): string {
  const rendered = error instanceof Error ? error.message : String(error);
  return /(?:web|relay)\.[a-z0-9_.]+/u.exec(rendered)?.[0] ?? "web.remote.pairing.failed";
}

function pairingEvidence(session: W2WasmSession): W2PairingEvidence {
  return JSON.parse(session.evidenceJson()) as W2PairingEvidence;
}

function businessEvidence(session: W2WasmSession): W2BusinessEvidence {
  return JSON.parse(session.businessEvidenceJson()) as W2BusinessEvidence;
}

async function completePairing(
  session: W2WasmSession,
  generation: number,
): Promise<W2TransportEvidence> {
  const preview = JSON.parse(session.previewJson()) as W2PairingPreview;
  let preConfirmNetworkLocked = false;
  try {
    session.connectUrl();
  } catch {
    preConfirmNetworkLocked = true;
  }
  session.confirm(preview.machineRootFingerprint, nowMs());
  const socket = new WebSocket(session.connectUrl());
  socket.binaryType = "arraybuffer";
  let binaryFramesSent = 0;

  try {
    await waitForOpen(socket, generation);
    socket.send(session.startHello());
    socket.send(session.startPairingHello());
    binaryFramesSent += 2;
    socket.send(session.acceptAuthenticated(await receiveBinary(socket, generation)));
    binaryFramesSent += 1;

    await withDeadline(
      (async () => {
        while (!session.paired()) {
          const action = session.acceptPairFrame(
            await receiveBinary(socket, generation),
            nowMs(),
          );
          if (action.length > 0) {
            socket.send(action);
            binaryFramesSent += 1;
          }
        }
      })(),
      PAIRING_TIMEOUT_MS,
      "web.remote.pairing.timeout",
    );
    return {
      generation,
      preview,
      preConfirmNetworkLocked,
      binaryFramesSent,
      pairing: pairingEvidence(session),
      failureCode: null,
    };
  } catch (error) {
    return {
      generation,
      preview,
      preConfirmNetworkLocked,
      binaryFramesSent,
      pairing: pairingEvidence(session),
      failureCode: failureCode(error),
    };
  } finally {
    await closeSocket(socket, "w2 pairing complete");
  }
}

function businessComplete(evidence: W2BusinessEvidence): boolean {
  return (
    evidence.principalAuthenticated &&
    evidence.catalogRouteAccepted &&
    evidence.catalogEntryCount === 1 &&
    evidence.catalogSubscriptionActive &&
    evidence.conversationRouteAccepted &&
    evidence.conversationOpen &&
    evidence.relaySubscriptionActive &&
    evidence.promptRouteAccepted &&
    evidence.promptAccepted &&
    evidence.assistantObserved &&
    evidence.approvalPending &&
    evidence.approvalSummaryMatched &&
    evidence.approvalRouteAccepted &&
    evidence.approvalReceiptApplied &&
    evidence.approvalEventApplied &&
    evidence.commandCompleted &&
    evidence.outerAckCount >= 5
  );
}

async function completeBusiness(
  session: W2WasmSession,
  generation: number,
): Promise<Readonly<{ evidence: W2BusinessEvidence; binaryFramesSent: number; failureCode: string | null }>> {
  const socket = new WebSocket(session.businessConnectUrl());
  socket.binaryType = "arraybuffer";
  let binaryFramesSent = 0;
  let conversationStarted = false;
  let promptStarted = false;
  let approvalStarted = false;
  let approvalReadbackStarted = false;
  let observedFenceCount = 0;
  try {
    await waitForOpen(socket, generation);
    socket.send(session.businessStartHello());
    binaryFramesSent += 1;
    socket.send(session.businessAcceptChallenge(await receiveBinary(socket, generation)));
    binaryFramesSent += 1;
    session.businessAcceptAuthenticated(await receiveBinary(socket, generation));
    socket.send(session.businessStartCatalog());
    binaryFramesSent += 1;

    await withDeadline(
      (async () => {
        while (!businessComplete(businessEvidence(session))) {
          const action = session.businessAcceptFrame(await receiveBinary(socket, generation));
          if (action.length > 0) {
            socket.send(action);
            binaryFramesSent += 1;
          }
          const evidence = businessEvidence(session);
          if (evidence.businessFenceCount > observedFenceCount) {
            observedFenceCount = evidence.businessFenceCount;
            if (observedFenceCount > 8) {
              throw new Error("web.remote.business.fence_retry_exhausted");
            }
            await new Promise<void>((resolve) => {
              setTimeout(resolve, Math.min(100 * observedFenceCount, 500));
            });
            if (!evidence.catalogSubscriptionActive) {
              socket.send(session.businessStartCatalog());
            } else if (!evidence.conversationOpen) {
              socket.send(session.businessStartConversation());
            } else if (!evidence.promptAccepted) {
              socket.send(session.businessStartPrompt());
            } else if (!evidence.approvalReceiptApplied) {
              socket.send(session.businessStartApproval());
            } else {
              throw new Error("web.remote.business.fence_stage_invalid");
            }
            binaryFramesSent += 1;
            continue;
          }
          if (
            !conversationStarted &&
            evidence.catalogRouteAccepted &&
            evidence.catalogEntryCount === 1 &&
            evidence.catalogSubscriptionActive
          ) {
            socket.send(session.businessStartConversation());
            binaryFramesSent += 1;
            conversationStarted = true;
          } else if (
            !promptStarted &&
            evidence.conversationOpen &&
            evidence.relaySubscriptionActive
          ) {
            socket.send(session.businessStartPrompt());
            binaryFramesSent += 1;
            promptStarted = true;
          } else if (
            !approvalStarted &&
            evidence.promptAccepted &&
            evidence.approvalPending
          ) {
            socket.send(session.businessStartApproval());
            binaryFramesSent += 1;
            approvalStarted = true;
          } else if (
            !approvalReadbackStarted &&
            evidence.approvalRouteAccepted &&
            evidence.approvalEventApplied &&
            !evidence.approvalReceiptApplied
          ) {
            socket.send(session.businessStartApproval());
            binaryFramesSent += 1;
            approvalReadbackStarted = true;
          }
        }
      })(),
      BUSINESS_TIMEOUT_MS,
      "web.remote.business.timeout",
    );
    return { evidence: businessEvidence(session), binaryFramesSent, failureCode: null };
  } catch (error) {
    return {
      evidence: businessEvidence(session),
      binaryFramesSent,
      failureCode: failureCode(error),
    };
  } finally {
    await closeSocket(socket, "w2 business complete");
  }
}

export async function runW2Pairing(
  Session: W2WasmSessionConstructor,
  encodedInvite: string,
): Promise<W2TransportEvidence> {
  if (activeGeneration !== null) {
    throw new Error("web.remote.single_flight");
  }
  const generation = ++nextGeneration;
  activeGeneration = generation;
  const session = new Session(encodedInvite, nowMs());
  try {
    return await completePairing(session, generation);
  } finally {
    session.free();
    if (activeGeneration === generation) {
      activeGeneration = null;
    }
  }
}

export async function runW2Business(
  Session: W2WasmSessionConstructor,
  encodedInvite: string,
): Promise<W2BusinessTransportEvidence> {
  if (activeGeneration !== null) {
    throw new Error("web.remote.single_flight");
  }
  const generation = ++nextGeneration;
  activeGeneration = generation;
  const session = new Session(encodedInvite, nowMs());
  try {
    const pairing = await completePairing(session, generation);
    if (pairing.failureCode !== null || !pairing.pairing.paired) {
      return {
        ...pairing,
        pairingBinaryFramesSent: pairing.binaryFramesSent,
        businessBinaryFramesSent: 0,
        business: null,
      };
    }
    const business = await completeBusiness(session, generation);
    return {
      ...pairing,
      binaryFramesSent: pairing.binaryFramesSent + business.binaryFramesSent,
      pairingBinaryFramesSent: pairing.binaryFramesSent,
      businessBinaryFramesSent: business.binaryFramesSent,
      business: business.evidence,
      failureCode: business.failureCode,
    };
  } finally {
    session.free();
    if (activeGeneration === generation) {
      activeGeneration = null;
    }
  }
}
