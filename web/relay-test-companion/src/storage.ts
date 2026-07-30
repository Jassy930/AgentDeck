import { assertExactRevisionTransition } from "./revision.ts";

const DATABASE_PREFIX = "agentdeck-relay-test-companion-w0";
const STORE_NAME = "durable";
const STATE_KEY = "state";
const KEK_KEY = "kek";
const PAIRED_KEY = "paired";
const REVOKED_KEY = "revoked";
const PAIRED_AAD_DOMAIN = "AgentDeck/WebPairedStateV1\0";

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

type EncryptedPairedRecord = Readonly<{
  key: typeof PAIRED_KEY;
  revision: number;
  iv: Uint8Array;
  ciphertext: Uint8Array;
}>;

type RevokedRecord = Readonly<{
  key: typeof REVOKED_KEY;
  revision: number;
  committedAtMs: number;
}>;

export type PairedStateLoad =
  | Readonly<{ status: "active"; revision: number; state: Uint8Array }>
  | Readonly<{ status: "revoked"; revision: number }>
  | Readonly<{ status: "missing" }>;

export type PairedStorageEvidence = Readonly<{
  pairedPresent: boolean;
  kekPresent: boolean;
  revokedPresent: boolean;
  revision: number | null;
  ciphertextBytes: number;
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

async function loadKek(profileId: string): Promise<CryptoKey | null> {
  const database = await openDatabase(profileId);
  try {
    const transaction = database.transaction(STORE_NAME, "readonly");
    const completed = transactionDone(transaction);
    const record = (await requestResult(transaction.objectStore(STORE_NAME).get(KEK_KEY))) as
      | { key: string; value: CryptoKey }
      | undefined;
    await completed;
    return record?.value instanceof CryptoKey ? record.value : null;
  } finally {
    database.close();
  }
}

async function ensureKek(profileId: string): Promise<CryptoKey> {
  const existing = await loadKek(profileId);
  if (existing !== null) {
    return existing;
  }
  const generated = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const database = await openDatabase(profileId);
  try {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    const completed = transactionDone(transaction);
    const store = transaction.objectStore(STORE_NAME);
    const raced = (await requestResult(store.get(KEK_KEY))) as
      | { key: string; value: CryptoKey }
      | undefined;
    if (raced === undefined) {
      await requestResult(store.add({ key: KEK_KEY, value: generated }));
      await completed;
      return generated;
    }
    await completed;
    if (!(raced.value instanceof CryptoKey)) {
      throw new Error("web.remote.storage.kekInvalid");
    }
    return raced.value;
  } finally {
    database.close();
  }
}

function cryptoBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(value);
}

function pairedAad(profileId: string, revision: number): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`${PAIRED_AAD_DOMAIN}${profileId}\0${revision}`);
}

async function encryptPairedState(
  profileId: string,
  revision: number,
  state: Uint8Array,
): Promise<Readonly<{ iv: Uint8Array; ciphertext: Uint8Array }>> {
  if (state.byteLength === 0 || state.byteLength > 256 * 1024) {
    throw new Error("web.remote.storage.pairedStateSizeInvalid");
  }
  const kek = await ensureKek(profileId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = cryptoBytes(state);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: pairedAad(profileId, revision) },
      kek,
      plaintext,
    ),
  );
  return { iv, ciphertext };
}

export async function promotePairedState(
  profileId: string,
  state: Uint8Array,
): Promise<number> {
  const encrypted = await encryptPairedState(profileId, 0, state);
  const database = await openDatabase(profileId);
  try {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    const completed = transactionDone(transaction);
    const store = transaction.objectStore(STORE_NAME);
    const [paired, revoked] = await Promise.all([
      requestResult(store.get(PAIRED_KEY)),
      requestResult(store.get(REVOKED_KEY)),
    ]);
    if (paired !== undefined || revoked !== undefined) {
      transaction.abort();
      await completed.catch(() => undefined);
      throw new Error("web.remote.storage.pairedPromotionConflict");
    }
    const record: EncryptedPairedRecord = {
      key: PAIRED_KEY,
      revision: 0,
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext,
    };
    await requestResult(store.add(record));
    await completed;
    return 0;
  } finally {
    database.close();
  }
}

export async function commitPairedState(
  profileId: string,
  expectedRevision: number,
  state: Uint8Array,
): Promise<number> {
  const nextRevision = expectedRevision + 1;
  if (!Number.isSafeInteger(nextRevision) || nextRevision <= expectedRevision) {
    throw new Error("web.remote.storage.revisionInvalid");
  }
  const encrypted = await encryptPairedState(profileId, nextRevision, state);
  const database = await openDatabase(profileId);
  try {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    const completed = transactionDone(transaction);
    const store = transaction.objectStore(STORE_NAME);
    const current = (await requestResult(store.get(PAIRED_KEY))) as
      | EncryptedPairedRecord
      | undefined;
    const revoked = await requestResult(store.get(REVOKED_KEY));
    if (current?.revision !== expectedRevision || revoked !== undefined) {
      transaction.abort();
      await completed.catch(() => undefined);
      throw new Error("web.remote.storage.pairedRevisionConflict");
    }
    await requestResult(
      store.put({
        key: PAIRED_KEY,
        revision: nextRevision,
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
      } satisfies EncryptedPairedRecord),
    );
    await completed;
    return nextRevision;
  } finally {
    database.close();
  }
}

export async function loadPairedState(profileId: string): Promise<PairedStateLoad> {
  const database = await openDatabase(profileId);
  let paired: EncryptedPairedRecord | undefined;
  let revoked: RevokedRecord | undefined;
  let kek: CryptoKey | undefined;
  try {
    const transaction = database.transaction(STORE_NAME, "readonly");
    const completed = transactionDone(transaction);
    const store = transaction.objectStore(STORE_NAME);
    [paired, revoked, kek] = await Promise.all([
      requestResult(store.get(PAIRED_KEY)) as Promise<EncryptedPairedRecord | undefined>,
      requestResult(store.get(REVOKED_KEY)) as Promise<RevokedRecord | undefined>,
      requestResult(store.get(KEK_KEY)).then(
        (record) => (record as { value?: CryptoKey } | undefined)?.value,
      ),
    ]);
    await completed;
  } finally {
    database.close();
  }
  if (revoked !== undefined) {
    if (paired !== undefined || kek !== undefined) {
      throw new Error("web.remote.storage.revokedMaterialPresent");
    }
    return { status: "revoked", revision: revoked.revision };
  }
  if (paired === undefined && kek === undefined) {
    return { status: "missing" };
  }
  if (paired === undefined || !(kek instanceof CryptoKey)) {
    throw new Error("web.remote.storage.pairedStateIncomplete");
  }
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: cryptoBytes(paired.iv),
      additionalData: pairedAad(profileId, paired.revision),
    },
    kek,
    cryptoBytes(paired.ciphertext),
  );
  return { status: "active", revision: paired.revision, state: new Uint8Array(plaintext) };
}

export async function commitRevokedCleanup(
  profileId: string,
  expectedRevision: number,
): Promise<number> {
  const nextRevision = expectedRevision + 1;
  const database = await openDatabase(profileId);
  try {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    const completed = transactionDone(transaction);
    const store = transaction.objectStore(STORE_NAME);
    const current = (await requestResult(store.get(PAIRED_KEY))) as
      | EncryptedPairedRecord
      | undefined;
    const revoked = await requestResult(store.get(REVOKED_KEY));
    if (current?.revision !== expectedRevision || revoked !== undefined) {
      transaction.abort();
      await completed.catch(() => undefined);
      throw new Error("web.remote.storage.revocationConflict");
    }
    await requestResult(
      store.put({
        key: REVOKED_KEY,
        revision: nextRevision,
        committedAtMs: Date.now(),
      } satisfies RevokedRecord),
    );
    await requestResult(store.delete(PAIRED_KEY));
    await requestResult(store.delete(KEK_KEY));
    await completed;
    return nextRevision;
  } finally {
    database.close();
  }
}

export async function inspectPairedStorage(profileId: string): Promise<PairedStorageEvidence> {
  const database = await openDatabase(profileId);
  try {
    const transaction = database.transaction(STORE_NAME, "readonly");
    const completed = transactionDone(transaction);
    const store = transaction.objectStore(STORE_NAME);
    const [paired, kek, revoked] = await Promise.all([
      requestResult(store.get(PAIRED_KEY)) as Promise<EncryptedPairedRecord | undefined>,
      requestResult(store.get(KEK_KEY)),
      requestResult(store.get(REVOKED_KEY)) as Promise<RevokedRecord | undefined>,
    ]);
    await completed;
    return {
      pairedPresent: paired !== undefined,
      kekPresent: kek !== undefined,
      revokedPresent: revoked !== undefined,
      revision: paired?.revision ?? revoked?.revision ?? null,
      ciphertextBytes: paired?.ciphertext.byteLength ?? 0,
    };
  } finally {
    database.close();
  }
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
