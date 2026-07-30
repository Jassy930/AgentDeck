import {
  acquireWriterLease,
  commitPairedProjectionState,
  commitExactRevision,
  createAndProveNonExtractableKek,
  deleteProfile,
  initializeState,
  inspectReservationStorage,
  loadPairedState,
  readState,
  type WriterLease,
} from "./storage.ts";
import {
  acquireWriterGeneration,
  type WriterGeneration,
} from "./writer-generation.ts";
import { runW1Transport, type W1WasmSessionConstructor } from "./w1-transport.ts";
import {
  runW2Business,
  runW2DurableRecover,
  runW2DurableStart,
  runW2Pairing,
  runW3ReservationCrash,
  runW3BrowserKillStart,
  runW3PendingBusinessCheckpoint,
  runW3ReconnectCheckpoint,
  runW3StateCrashStart,
  runW3StateForkProbe,
  type W2WasmSessionConstructor,
} from "./w2-transport.ts";

type WebCoreModule = Readonly<{
  default: () => Promise<unknown>;
  w0ContractSnapshot: () => string;
  w0NegativeSnapshot: () => string;
  w0RelayHello: () => Uint8Array;
  w0ValidateRelayFrame: (bytes: Uint8Array) => void;
  w0RuntimeRequestRoundtrip: (bytes: Uint8Array) => Uint8Array;
  w0CryptoTamperIsRejected: () => boolean;
  w2NegativeSnapshot?: () => string;
  W1Session?: W1WasmSessionConstructor;
  W2PairingSession?: W2WasmSessionConstructor;
}>;

const wasmModuleUrl = "/wasm/agentdeck_web_core.js";
const leases = new Map<string, WriterLease>();
const writerGenerations = new Map<string, WriterGeneration>();

const corePromise = (async (): Promise<WebCoreModule> => {
  const core = (await import(wasmModuleUrl)) as WebCoreModule;
  await core.default();
  return core;
})();

function bytes(input: readonly number[]): Uint8Array {
  return Uint8Array.from(input);
}

function failureCode(error: unknown): string {
  const rendered = error instanceof Error ? error.message : String(error);
  return /(?:web|relay)\.[a-z0-9_.]+/u.exec(rendered)?.[0] ?? "web.remote.unexpected";
}

async function ensureWriterGeneration(profileId: string): Promise<WriterGeneration> {
  const current = writerGenerations.get(profileId);
  if (current !== undefined) {
    try {
      current.assertCurrent();
      return current;
    } catch {
      writerGenerations.delete(profileId);
      await current.close();
    }
  }
  const generation = await acquireWriterGeneration(profileId);
  if (!generation.acquired) {
    await generation.close();
    throw new Error("web.remote.writer_locked");
  }
  writerGenerations.set(profileId, generation);
  return generation;
}

async function closeWriterGeneration(profileId: string): Promise<void> {
  const generation = writerGenerations.get(profileId);
  writerGenerations.delete(profileId);
  await generation?.close();
}

async function rejectsRelayFrame(input: readonly number[]): Promise<boolean> {
  const core = await corePromise;
  try {
    core.w0ValidateRelayFrame(bytes(input));
    return false;
  } catch {
    return true;
  }
}

const api: RelayTestApi = {
  async contractSnapshot() {
    return JSON.parse((await corePromise).w0ContractSnapshot()) as Record<string, string>;
  },
  async negativeSnapshot() {
    return JSON.parse((await corePromise).w0NegativeSnapshot()) as Record<string, boolean>;
  },
  async relayHello() {
    return Array.from((await corePromise).w0RelayHello());
  },
  async relayFrameRejected(input) {
    return rejectsRelayFrame(input);
  },
  async runtimeRoundtrip(input) {
    return Array.from((await corePromise).w0RuntimeRequestRoundtrip(bytes(input)));
  },
  async runtimeRejected(input) {
    try {
      (await corePromise).w0RuntimeRequestRoundtrip(bytes(input));
      return false;
    } catch {
      return true;
    }
  },
  async cryptoTamperRejected() {
    return (await corePromise).w0CryptoTamperIsRejected();
  },
  async w2NegativeSnapshot() {
    const snapshot = (await corePromise).w2NegativeSnapshot;
    if (snapshot === undefined) {
      throw new Error("web.remote.w2_fixture_unavailable");
    }
    return JSON.parse(snapshot()) as W2NegativeEvidence;
  },
  async runW1Transport(origin, relayServerIdHex, caseName) {
    const constructor = (await corePromise).W1Session;
    if (constructor === undefined) {
      throw new Error("web.remote.w1_fixture_unavailable");
    }
    const result = await runW1Transport(constructor, origin, relayServerIdHex, caseName);
    const status = document.querySelector<HTMLElement>("#w1-status");
    if (status !== null) {
      status.dataset.state = result.sentinelAccepted ? "passed" : "failed";
      status.textContent = result.sentinelAccepted ? "W1 真实 Relay 通过" : result.failureCode;
    }
    return result;
  },
  async runW2Pairing(encodedInvite) {
    const constructor = (await corePromise).W2PairingSession;
    if (constructor === undefined) {
      throw new Error("web.remote.w2_fixture_unavailable");
    }
    const result = await runW2Pairing(constructor, encodedInvite);
    const status = document.querySelector<HTMLElement>("#w2-status");
    if (status !== null) {
      status.dataset.state = result.pairing.paired ? "passed" : "failed";
      status.textContent = result.pairing.paired
        ? "W2a 真实配对通过"
        : (result.failureCode ?? "W2a 配对失败");
    }
    return result;
  },
  async runW2Business(encodedInvite) {
    const constructor = (await corePromise).W2PairingSession;
    if (constructor === undefined) {
      throw new Error("web.remote.w2_fixture_unavailable");
    }
    const result = await runW2Business(constructor, encodedInvite);
    const passed =
      result.failureCode === null &&
      result.business?.commandCompleted === true &&
      result.business.approvalReceiptApplied &&
      result.business.approvalEventApplied;
    const status = document.querySelector<HTMLElement>("#w2-status");
    if (status !== null) {
      status.dataset.state = passed ? "passed" : "failed";
      status.textContent = passed
        ? "W2b 真实业务闭环通过"
        : (result.failureCode ?? "W2b 业务闭环失败");
    }
    return result;
  },
  async runW2DurableStart(encodedInvite, profileId) {
    const constructor = (await corePromise).W2PairingSession;
    if (constructor === undefined) {
      throw new Error("web.remote.w2_fixture_unavailable");
    }
    await ensureWriterGeneration(profileId);
    const result = await runW2DurableStart(constructor, encodedInvite, profileId).catch(async (error) => {
      await closeWriterGeneration(profileId);
      throw error;
    });
    if (result.failureCode !== null) {
      await closeWriterGeneration(profileId);
    }
    const status = document.querySelector<HTMLElement>("#w2-status");
    if (status !== null) {
      status.dataset.state = result.failureCode === null ? "running" : "failed";
      status.textContent = result.failureCode === null
        ? "W2c 已持久化，等待 reload"
        : result.failureCode;
    }
    return result;
  },
  async runW2DurableRecover(profileId) {
    const constructor = (await corePromise).W2PairingSession;
    if (constructor === undefined) {
      throw new Error("web.remote.w2_fixture_unavailable");
    }
    await ensureWriterGeneration(profileId);
    const result = await runW2DurableRecover(constructor, profileId).finally(() =>
      closeWriterGeneration(profileId),
    );
    const passed =
      result.failureCode === null &&
      result.reloadStatus === "revoked" &&
      result.business?.revocationTerminalVerified === true;
    const status = document.querySelector<HTMLElement>("#w2-status");
    if (status !== null) {
      status.dataset.state = passed ? "passed" : "failed";
      status.textContent = passed
        ? "W2c reload/reconnect/revoke 闭环通过"
        : (result.failureCode ?? "W2c 恢复闭环失败");
    }
    return result;
  },
  async runW3ReservationCrash(profileId, cut) {
    const constructor = (await corePromise).W2PairingSession;
    if (constructor === undefined) {
      throw new Error("web.remote.w2_fixture_unavailable");
    }
    await ensureWriterGeneration(profileId);
    const result = await runW3ReservationCrash(constructor, profileId, cut).catch(async (error) => {
      await closeWriterGeneration(profileId);
      throw error;
    });
    if (result.failureCode !== null) {
      await closeWriterGeneration(profileId);
    }
    return result;
  },
  async runW3StateCrashStart(encodedInvite, profileId, cut) {
    const constructor = (await corePromise).W2PairingSession;
    if (constructor === undefined) {
      throw new Error("web.remote.w2_fixture_unavailable");
    }
    await ensureWriterGeneration(profileId);
    const result = await runW3StateCrashStart(constructor, encodedInvite, profileId, cut).catch(
      async (error) => {
        await closeWriterGeneration(profileId);
        throw error;
      },
    );
    if (result.failureCode !== null) {
      await closeWriterGeneration(profileId);
    }
    return result;
  },
  async runW3StateForkProbe(profileId) {
    await ensureWriterGeneration(profileId);
    try {
      return await runW3StateForkProbe(profileId);
    } finally {
      await closeWriterGeneration(profileId);
    }
  },
  async acquireWriterGeneration(profileId) {
    try {
      await ensureWriterGeneration(profileId);
      return true;
    } catch (error) {
      if (failureCode(error) === "web.remote.writer_locked") {
        return false;
      }
      throw error;
    }
  },
  async relinquishWriterGeneration(profileId) {
    const generation = writerGenerations.get(profileId);
    if (generation === undefined) {
      throw new Error("web.remote.writer_generation_missing");
    }
    await generation.relinquish();
  },
  async releaseWriterGeneration(profileId) {
    await closeWriterGeneration(profileId);
  },
  writerGenerationSnapshot(profileId) {
    return writerGenerations.get(profileId)?.snapshot() ?? null;
  },
  async runW3LateGenerationProbe(profileId) {
    const before = await inspectReservationStorage(profileId);
    let rejectionCode: string | null = null;
    let binaryFramesSent = 0;
    try {
      const generation = writerGenerations.get(profileId);
      if (generation === undefined) {
        throw new Error("web.remote.writer_generation_missing");
      }
      generation.assertCurrent();
      const loaded = await loadPairedState(profileId);
      if (loaded.status !== "active") {
        throw new Error(`web.remote.durable.${loaded.status}`);
      }
      generation.assertCurrent();
      await commitPairedProjectionState(profileId, loaded.revision, loaded.state);
      generation.assertCurrent();
      binaryFramesSent += 1;
    } catch (error) {
      rejectionCode = failureCode(error);
    }
    const after = await inspectReservationStorage(profileId);
    const canonicalMutationCount =
      before.pairedRevision === after.pairedRevision && before.guardPhase === after.guardPhase ? 0 : 1;
    const expectedRejection =
      rejectionCode === "web.remote.writer_generation_missing" ||
      rejectionCode === "web.remote.generation_stale";
    return {
      rejectionCode,
      binaryFramesSent,
      canonicalMutationCount,
      pairedRevisionBefore: before.pairedRevision,
      pairedRevisionAfter: after.pairedRevision,
      guardPhaseBefore: before.guardPhase,
      guardPhaseAfter: after.guardPhase,
      failureCode:
        expectedRejection && binaryFramesSent === 0 && canonicalMutationCount === 0
          ? null
          : "web.remote.durable.writer_contention_probe_failed",
    };
  },
  async runW3BrowserKillStart(encodedInvite, profileId, cut) {
    const constructor = (await corePromise).W2PairingSession;
    if (constructor === undefined) {
      throw new Error("web.remote.w2_fixture_unavailable");
    }
    await ensureWriterGeneration(profileId);
    const result = await runW3BrowserKillStart(
      constructor,
      encodedInvite,
      profileId,
      cut,
    ).catch(async (error) => {
      await closeWriterGeneration(profileId);
      throw error;
    });
    if (result.failureCode !== null) {
      await closeWriterGeneration(profileId);
    }
    return result;
  },
  async runW3ReconnectCheckpoint(profileId) {
    const constructor = (await corePromise).W2PairingSession;
    if (constructor === undefined) {
      throw new Error("web.remote.w2_fixture_unavailable");
    }
    await ensureWriterGeneration(profileId);
    const result = await runW3ReconnectCheckpoint(constructor, profileId).catch(async (error) => {
      await closeWriterGeneration(profileId);
      throw error;
    });
    if (result.failureCode !== null) {
      await closeWriterGeneration(profileId);
    }
    return result;
  },
  async runW3PendingBusinessCheckpoint(profileId) {
    const constructor = (await corePromise).W2PairingSession;
    if (constructor === undefined) {
      throw new Error("web.remote.w2_fixture_unavailable");
    }
    await ensureWriterGeneration(profileId);
    const result = await runW3PendingBusinessCheckpoint(constructor, profileId).catch(async (error) => {
      await closeWriterGeneration(profileId);
      throw error;
    });
    if (result.failureCode !== null) {
      await closeWriterGeneration(profileId);
    }
    return result;
  },
  initializeState,
  readState,
  commitExactRevision,
  createAndProveNonExtractableKek,
  async acquireWriter(profileId) {
    const current = leases.get(profileId);
    if (current?.acquired === true) {
      return true;
    }
    const lease = await acquireWriterLease(profileId);
    if (lease.acquired) {
      leases.set(profileId, lease);
    } else {
      await lease.release();
    }
    return lease.acquired;
  },
  async releaseWriter(profileId) {
    const lease = leases.get(profileId);
    leases.delete(profileId);
    await lease?.release();
  },
  async deleteProfile(profileId) {
    await closeWriterGeneration(profileId);
    const lease = leases.get(profileId);
    leases.delete(profileId);
    await lease?.release();
    await deleteProfile(profileId);
  },
};

globalThis.relayTestApi = api;

async function runPageSelfcheck(): Promise<void> {
  const button = document.querySelector<HTMLButtonElement>("#run-selfcheck");
  const status = document.querySelector<HTMLElement>("#w0-status");
  const evidence = document.querySelector<HTMLElement>("#evidence");
  if (button === null || status === null || evidence === null) {
    return;
  }
  button.disabled = true;
  status.dataset.state = "running";
  status.textContent = "W0 运行中";
  try {
    const [snapshot, negatives, tamperRejected] = await Promise.all([
      api.contractSnapshot(),
      api.negativeSnapshot(),
      api.cryptoTamperRejected(),
    ]);
    const passed = Object.values(negatives).every(Boolean) && tamperRejected;
    evidence.textContent = [
      `Relay Hello: ${snapshot.relayHelloHex ?? "missing"}`,
      `共享向量: ${Object.keys(snapshot).length}`,
      `密码学负例: ${Object.values(negatives).filter(Boolean).length}/${Object.keys(negatives).length}`,
    ].join("\n");
    status.dataset.state = passed ? "passed" : "failed";
    status.textContent = passed ? "W0 核心通过" : "W0 核心失败";
  } catch (error) {
    status.dataset.state = "failed";
    status.textContent = "W0 核心失败";
    evidence.textContent = error instanceof Error ? error.message : "unknown failure";
  } finally {
    button.disabled = false;
  }
}

document.querySelector("#run-selfcheck")?.addEventListener("click", () => {
  void runPageSelfcheck();
});
void corePromise.then(() => {
  document.documentElement.dataset.ready = "true";
});
