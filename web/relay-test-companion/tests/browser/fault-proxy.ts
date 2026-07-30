import { existsSync, chmodSync, renameSync, writeFileSync } from "node:fs";
import { createServer, connect, type Socket } from "node:net";

type FaultMode = "disconnect" | "delay" | "relayRestart";

const listenPort = Number.parseInt(process.env.AGENTDECK_W3_PROXY_LISTEN_PORT ?? "", 10);
const targetPort = Number.parseInt(process.env.AGENTDECK_W3_PROXY_TARGET_PORT ?? "", 10);
const controlDir = process.env.AGENTDECK_W3_PROXY_CONTROL_DIR;
const mode = process.env.AGENTDECK_W3_NETWORK_FAULT as FaultMode | undefined;
if (
  !Number.isSafeInteger(listenPort) ||
  listenPort < 1 ||
  listenPort > 65_535 ||
  !Number.isSafeInteger(targetPort) ||
  targetPort < 1 ||
  targetPort > 65_535 ||
  controlDir === undefined ||
  !["disconnect", "delay", "relayRestart"].includes(mode ?? "")
) {
  throw new Error("web.remote.test.fault_proxy_config_invalid");
}

const armPath = `${controlDir}/proxy.arm`;
const readyPath = `${controlDir}/proxy.ready.json`;
const evidencePath = `${controlDir}/proxy.evidence.json`;
const triggerBytes = 2 * 1_024;
const delayMs = 120;
let nextConnectionId = 0;
let faultConsumed = false;
let faultConnectionId: number | null = null;
let faultTriggered = false;
let clientToServerBytes = 0;
let serverToClientBytes = 0;
let faultConnectionClientToServerBytes = 0;
let faultConnectionServerToClientBytes = 0;
let delayApplications = 0;
const sockets = new Set<Socket>();

function writePrivateJson(path: string, value: unknown): void {
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value)}\n`, { flag: "w", mode: 0o600 });
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
}

function writeEvidence(): void {
  writePrivateJson(evidencePath, {
    schemaVersion: 1,
    mode,
    parsedProtocol: false,
    connectionCount: nextConnectionId,
    faultConnectionId,
    faultTriggered,
    clientToServerBytes,
    serverToClientBytes,
    faultConnectionClientToServerBytes,
    faultConnectionServerToClientBytes,
    delayApplications,
  });
}

function destroyPair(client: Socket, upstream: Socket): void {
  client.destroy();
  upstream.destroy();
}

function maybeTrigger(client: Socket, upstream: Socket, connectionId: number): void {
  if (
    faultTriggered ||
    faultConnectionId !== connectionId ||
    faultConnectionClientToServerBytes + faultConnectionServerToClientBytes < triggerBytes
  ) {
    return;
  }
  faultTriggered = true;
  writeEvidence();
  if (mode === "disconnect") {
    destroyPair(client, upstream);
  }
}

function forward(
  source: Socket,
  destination: Socket,
  client: Socket,
  upstream: Socket,
  connectionId: number,
  direction: "clientToServer" | "serverToClient",
  delayed: boolean,
): void {
  source.on("data", (chunk: Buffer) => {
    if (direction === "clientToServer") {
      clientToServerBytes += chunk.byteLength;
      if (faultConnectionId === connectionId) {
        faultConnectionClientToServerBytes += chunk.byteLength;
      }
    } else {
      serverToClientBytes += chunk.byteLength;
      if (faultConnectionId === connectionId) {
        faultConnectionServerToClientBytes += chunk.byteLength;
      }
    }
    const deliver = (): boolean => {
      if (destination.destroyed) {
        return false;
      }
      const accepted = destination.write(chunk);
      if (!accepted) {
        source.pause();
        destination.once("drain", () => source.resume());
      }
      maybeTrigger(client, upstream, connectionId);
      return accepted;
    };
    if (delayed) {
      source.pause();
      delayApplications += 1;
      setTimeout(() => {
        const accepted = deliver();
        if (accepted && !source.destroyed) {
          source.resume();
        }
        writeEvidence();
      }, delayMs);
    } else {
      deliver();
    }
  });
}

const server = createServer((client) => {
  const connectionId = ++nextConnectionId;
  const armed = !faultConsumed && existsSync(armPath);
  if (armed) {
    faultConsumed = true;
    faultConnectionId = connectionId;
  }
  const upstream = connect({ host: "127.0.0.1", port: targetPort });
  sockets.add(client);
  sockets.add(upstream);
  const cleanup = (): void => {
    sockets.delete(client);
    sockets.delete(upstream);
    writeEvidence();
  };
  client.once("close", cleanup);
  client.on("error", () => destroyPair(client, upstream));
  upstream.on("error", () => destroyPair(client, upstream));
  upstream.once("close", () => client.destroy());
  const delayed = armed && mode === "delay";
  forward(client, upstream, client, upstream, connectionId, "clientToServer", delayed);
  forward(upstream, client, client, upstream, connectionId, "serverToClient", false);
  if (armed && mode === "delay") {
    faultTriggered = true;
  }
  writeEvidence();
});

server.listen(listenPort, "127.0.0.1", () => {
  writePrivateJson(readyPath, {
    schemaVersion: 1,
    listenPort,
    targetPort,
    mode,
    parsedProtocol: false,
  });
  writeEvidence();
});
server.on("error", (error) => {
  throw error;
});

function shutdown(): void {
  for (const socket of sockets) {
    socket.destroy();
  }
  writeEvidence();
  server.close(() => process.exit(0));
}

process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
