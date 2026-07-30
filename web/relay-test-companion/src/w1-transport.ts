export type W1TransportCase =
  | "positive"
  | "wrongServer"
  | "tamperChallenge"
  | "tamperSignature"
  | "replayAuthenticate"
  | "textFrame"
  | "oversizeFrame"
  | "disconnect"
  | "unavailable";

export type W1TransportEvidence = Readonly<{
  caseName: W1TransportCase;
  generation: number;
  authenticated: boolean;
  sentinelAccepted: boolean;
  binaryFramesSent: number;
  failureCode: string | null;
}>;

type W1WasmSession = Readonly<{
  connectUrl: () => string;
  start: () => Uint8Array;
  acceptChallenge: (bytes: Uint8Array, fault: string) => Uint8Array;
  acceptAuthenticated: (bytes: Uint8Array) => void;
  registerStream: () => Uint8Array;
  publishSentinel: () => Uint8Array;
  acceptActiveFrame: (bytes: Uint8Array) => Uint8Array;
  sentinelAccepted: () => boolean;
  oversizeFaultFrame: () => Uint8Array;
  free: () => void;
}>;

export type W1WasmSessionConstructor = new (
  origin: string,
  expectedRelayServerId: Uint8Array,
) => W1WasmSession;

const CONNECT_TIMEOUT_MS = 5_000;
const IO_TIMEOUT_MS = 3_000;
let nextGeneration = 0;
let activeGeneration: number | null = null;

function relayServerId(hex: string): Uint8Array {
  if (!/^[0-9a-f]{32}$/u.test(hex)) {
    throw new Error("web.remote.server_identity_invalid");
  }
  const output = new Uint8Array(16);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

function failureCode(error: unknown, fallback: string): string {
  const rendered = error instanceof Error ? error.message : String(error);
  const match = /(?:web|relay)\.[a-z0-9_.]+/u.exec(rendered);
  return match?.[0] ?? fallback;
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
      const cleanup = (): void => {
        socket.removeEventListener("open", opened);
        socket.removeEventListener("error", failed);
        socket.removeEventListener("close", closed);
      };
      const opened = (): void => {
        cleanup();
        if (activeGeneration === generation) {
          resolve();
        } else {
          reject(new Error("web.remote.generation_stale"));
        }
      };
      const failed = (): void => {
        cleanup();
        reject(new Error("web.remote.connect_failed"));
      };
      const closed = (): void => {
        cleanup();
        reject(new Error("web.remote.connection_closed"));
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
  return withDeadline(
    new Promise<Uint8Array>((resolve, reject) => {
      const cleanup = (): void => {
        socket.removeEventListener("message", received);
        socket.removeEventListener("error", failed);
        socket.removeEventListener("close", closed);
      };
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
      socket.addEventListener("message", received, { once: true });
      socket.addEventListener("error", failed, { once: true });
      socket.addEventListener("close", closed, { once: true });
    }),
    IO_TIMEOUT_MS,
    "web.remote.receive_timeout",
  );
}

function waitForClose(socket: WebSocket): Promise<void> {
  if (socket.readyState === WebSocket.CLOSED) {
    return Promise.resolve();
  }
  return withDeadline(
    new Promise<void>((resolve) => {
      socket.addEventListener("close", () => resolve(), { once: true });
    }),
    IO_TIMEOUT_MS,
    "web.remote.close_timeout",
  );
}

async function closeSocket(socket: WebSocket): Promise<void> {
  if (socket.readyState === WebSocket.CLOSING || socket.readyState === WebSocket.CLOSED) {
    await waitForClose(socket).catch(() => undefined);
    return;
  }
  socket.close(1000, "w1 complete");
  await waitForClose(socket).catch(() => undefined);
}

function evidence(
  caseName: W1TransportCase,
  generation: number,
  authenticated: boolean,
  sentinelAccepted: boolean,
  binaryFramesSent: number,
  failureCodeValue: string | null,
): W1TransportEvidence {
  return {
    caseName,
    generation,
    authenticated,
    sentinelAccepted,
    binaryFramesSent,
    failureCode: failureCodeValue,
  };
}

export async function runW1Transport(
  Session: W1WasmSessionConstructor,
  origin: string,
  relayServerIdHex: string,
  caseName: W1TransportCase,
): Promise<W1TransportEvidence> {
  if (activeGeneration !== null) {
    throw new Error("web.remote.single_flight");
  }
  const generation = ++nextGeneration;
  activeGeneration = generation;
  const session = new Session(origin, relayServerId(relayServerIdHex));
  const socket = new WebSocket(session.connectUrl());
  socket.binaryType = "arraybuffer";
  let binaryFramesSent = 0;
  let authenticated = false;

  try {
    try {
      await waitForOpen(socket, generation);
    } catch (error) {
      if (caseName === "unavailable") {
        return evidence(
          caseName,
          generation,
          false,
          false,
          0,
          "web.remote.connect_failed",
        );
      }
      throw error;
    }

    if (caseName === "textFrame") {
      socket.send("w1-text-fault");
      await waitForClose(socket);
      return evidence(caseName, generation, false, false, 0, "web.remote.text_frame_rejected");
    }
    if (caseName === "oversizeFrame") {
      socket.send(session.oversizeFaultFrame());
      binaryFramesSent += 1;
      await waitForClose(socket);
      return evidence(caseName, generation, false, false, binaryFramesSent, "web.remote.frame_too_large");
    }
    if (caseName === "disconnect") {
      await closeSocket(socket);
      return evidence(caseName, generation, false, false, 0, "web.remote.disconnected");
    }

    socket.send(session.start());
    binaryFramesSent += 1;
    const challenge = await receiveBinary(socket, generation);
    const fault =
      caseName === "tamperChallenge"
        ? "tamperChallenge"
        : caseName === "tamperSignature"
          ? "tamperSignature"
          : "none";
    let authenticate: Uint8Array;
    try {
      authenticate = session.acceptChallenge(challenge, fault);
    } catch (error) {
      if (caseName === "wrongServer") {
        return evidence(
          caseName,
          generation,
          false,
          false,
          binaryFramesSent,
          failureCode(error, "web.remote.server_identity_mismatch"),
        );
      }
      throw error;
    }
    socket.send(authenticate);
    binaryFramesSent += 1;

    let authenticatedFrame: Uint8Array;
    try {
      authenticatedFrame = await receiveBinary(socket, generation);
      session.acceptAuthenticated(authenticatedFrame);
    } catch {
      if (caseName === "tamperChallenge" || caseName === "tamperSignature") {
        return evidence(
          caseName,
          generation,
          false,
          false,
          binaryFramesSent,
          "web.remote.handshake_rejected",
        );
      }
      throw new Error("web.remote.handshake_rejected");
    }
    authenticated = true;

    if (caseName === "replayAuthenticate") {
      socket.send(authenticate);
      binaryFramesSent += 1;
      const rejected = await receiveBinary(socket, generation);
      try {
        session.acceptActiveFrame(rejected);
      } catch {
        return evidence(
          caseName,
          generation,
          true,
          false,
          binaryFramesSent,
          "web.remote.replay_rejected",
        );
      }
      throw new Error("web.remote.replay_accepted");
    }

    socket.send(session.registerStream());
    binaryFramesSent += 1;
    socket.send(session.publishSentinel());
    binaryFramesSent += 1;
    for (let received = 0; received < 8 && !session.sentinelAccepted(); received += 1) {
      const action = session.acceptActiveFrame(await receiveBinary(socket, generation));
      if (action.length > 0) {
        socket.send(action);
        binaryFramesSent += 1;
      }
    }
    if (!session.sentinelAccepted()) {
      throw new Error("web.remote.sentinel_not_accepted");
    }
    return evidence(caseName, generation, true, true, binaryFramesSent, null);
  } finally {
    await closeSocket(socket);
    session.free();
    if (activeGeneration === generation) {
      activeGeneration = null;
    }
  }
}
