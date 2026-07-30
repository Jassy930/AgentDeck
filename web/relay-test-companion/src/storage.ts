import { assertExactRevisionTransition } from "./revision.ts";

const DATABASE_PREFIX = "agentdeck-relay-test-companion-w0";
const STORE_NAME = "durable";
const STATE_KEY = "state";
const KEK_KEY = "kek";

type DurableRecord = Readonly<{
  key: string;
  revision: number;
  payload: string;
}>;

export type KekProof = Readonly<{
  algorithm: string;
  extractable: boolean;
  roundtrip: boolean;
  exportRejected: boolean;
}>;

export type WriterLease = Readonly<{
  acquired: boolean;
  release: () => Promise<void>;
}>;

function databaseName(profileId: string): string {
  if (!/^[a-z0-9-]{1,64}$/u.test(profileId)) {
    throw new Error("web.remote.storage.invalidProfileId");
  }
  return `${DATABASE_PREFIX}-${profileId}`;
}
function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.addEventListener("success", () => resolve(request.result), { once: true });
    request.addEventListener("error", () => reject(request.error), { once: true });
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.addEventListener("complete", () => resolve(), { once: true });
    transaction.addEventListener(
      "abort",
      () => reject(transaction.error ?? new DOMException("aborted", "AbortError")),
      { once: true },
    );
    transaction.addEventListener("error", () => reject(transaction.error), { once: true });
  });
}

async function openDatabase(profileId: string): Promise<IDBDatabase> {
  const request = indexedDB.open(databaseName(profileId), 1);
  request.addEventListener("upgradeneeded", () => {
    const database = request.result;
    if (!database.objectStoreNames.contains(STORE_NAME)) {
      database.createObjectStore(STORE_NAME, { keyPath: "key" });
    }
  });
  return requestResult(request);
}

export async function initializeState(profileId: string, payload: string): Promise<DurableRecord> {
  const database = await openDatabase(profileId);
  try {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    const completed = transactionDone(transaction);
    const store = transaction.objectStore(STORE_NAME);
    const existing = (await requestResult(store.get(STATE_KEY))) as DurableRecord | undefined;
    if (existing !== undefined) {
      transaction.abort();
      await completed.catch(() => undefined);
      return existing;
    }
    const initial: DurableRecord = { key: STATE_KEY, revision: 0, payload };
    await requestResult(store.add(initial));
    await completed;
    return initial;
  } finally {
    database.close();
  }
}

export async function readState(profileId: string): Promise<DurableRecord | null> {
  const database = await openDatabase(profileId);
  try {
    const transaction = database.transaction(STORE_NAME, "readonly");
    const completed = transactionDone(transaction);
    const record = (await requestResult(
      transaction.objectStore(STORE_NAME).get(STATE_KEY),
    )) as DurableRecord | undefined;
    await completed;
    return record ?? null;
  } finally {
    database.close();
  }
}

export async function commitExactRevision(
  profileId: string,
  expectedRevision: number,
  nextRevision: number,
  payload: string,
  abortAfterPut = false,
): Promise<DurableRecord> {
  const database = await openDatabase(profileId);
  try {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    const completed = transactionDone(transaction);
    const store = transaction.objectStore(STORE_NAME);
    const current = (await requestResult(store.get(STATE_KEY))) as DurableRecord | undefined;
    if (current === undefined) {
      transaction.abort();
      await completed.catch(() => undefined);
      throw new Error("web.remote.storage.stateMissing");
    }

    try {
      assertExactRevisionTransition({
        actualRevision: current.revision,
        expectedRevision,
        nextRevision,
      });
    } catch (error) {
      transaction.abort();
      await completed.catch(() => undefined);
      throw error;
    }

    const next: DurableRecord = { key: STATE_KEY, revision: nextRevision, payload };
    await requestResult(store.put(next));
    if (abortAfterPut) {
      transaction.abort();
      await completed.catch(() => undefined);
      return (await readState(profileId)) ?? current;
    }
    await completed;
    return next;
  } finally {
    database.close();
  }
}

export async function createAndProveNonExtractableKek(profileId: string): Promise<KekProof> {
  const database = await openDatabase(profileId);
  try {
    const generated = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    const transaction = database.transaction(STORE_NAME, "readwrite");
    const completed = transactionDone(transaction);
    await requestResult(transaction.objectStore(STORE_NAME).put({ key: KEK_KEY, value: generated }));
    await completed;
  } finally {
    database.close();
  }

  const reopened = await openDatabase(profileId);
  let stored: CryptoKey;
  try {
    const transaction = reopened.transaction(STORE_NAME, "readonly");
    const completed = transactionDone(transaction);
    const record = (await requestResult(transaction.objectStore(STORE_NAME).get(KEK_KEY))) as
      | { key: string; value: CryptoKey }
      | undefined;
    await completed;
    if (!(record?.value instanceof CryptoKey)) {
      throw new Error("web.remote.storage.kekCloneFailed");
    }
    stored = record.value;
  } finally {
    reopened.close();
  }

  const plaintext = new TextEncoder().encode("w0-non-extractable-kek");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, stored, plaintext);
  const recovered = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, stored, ciphertext);
  let exportRejected = false;
  try {
    await crypto.subtle.exportKey("raw", stored);
  } catch {
    exportRejected = true;
  }

  return {
    algorithm: stored.algorithm.name,
    extractable: stored.extractable,
    roundtrip: new TextDecoder().decode(recovered) === "w0-non-extractable-kek",
    exportRejected,
  };
}

export async function acquireWriterLease(profileId: string): Promise<WriterLease> {
  const lockName = `${DATABASE_PREFIX}-writer-${profileId}`;
  let announce: ((acquired: boolean) => void) | undefined;
  let releaseHold: (() => void) | undefined;
  const announced = new Promise<boolean>((resolve) => {
    announce = resolve;
  });
  const hold = new Promise<void>((resolve) => {
    releaseHold = resolve;
  });

  const request = navigator.locks.request(
    lockName,
    { mode: "exclusive", ifAvailable: true },
    async (lock) => {
      announce?.(lock !== null);
      if (lock !== null) {
        await hold;
      }
    },
  );
  const acquired = await announced;
  let released = false;
  return {
    acquired,
    release: async () => {
      if (!released) {
        released = true;
        releaseHold?.();
      }
      await request;
    },
  };
}

export async function deleteProfile(profileId: string): Promise<void> {
  const request = indexedDB.deleteDatabase(databaseName(profileId));
  await requestResult(request);
}
