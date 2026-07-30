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
  free: () => void;
}>;

export type W2WasmSessionConstructor = new (
  encodedInvite: string,
  nowMs: bigint,
) => W2WasmSession;

const CONNECT_TIMEOUT_MS = 5_000;
const PAIRING_TIMEOUT_MS = 120_000;
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

async function closeSocket(socket: WebSocket): Promise<void> {
  if (socket.readyState === WebSocket.CLOSED) {
    return;
  }
  const closed = new Promise<void>((resolve) => {
    socket.addEventListener("close", () => resolve(), { once: true });
  });
  if (socket.readyState !== WebSocket.CLOSING) {
    socket.close(1000, "w2a complete");
  }
  await withDeadline(closed, 3_000, "web.remote.close_timeout").catch(() => undefined);
}

function failureCode(error: unknown): string {
  const rendered = error instanceof Error ? error.message : String(error);
  return /(?:web|relay)\.[a-z0-9_.]+/u.exec(rendered)?.[0] ?? "web.remote.pairing.failed";
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
      pairing: JSON.parse(session.evidenceJson()) as W2PairingEvidence,
      failureCode: null,
    };
  } catch (error) {
    return {
      generation,
      preview,
      preConfirmNetworkLocked,
      binaryFramesSent,
      pairing: JSON.parse(session.evidenceJson()) as W2PairingEvidence,
      failureCode: failureCode(error),
    };
  } finally {
    await closeSocket(socket);
    session.free();
    if (activeGeneration === generation) {
      activeGeneration = null;
    }
  }
}
