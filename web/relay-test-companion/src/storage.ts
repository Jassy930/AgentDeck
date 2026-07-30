import { assertExactRevisionTransition } from "./revision.ts";

const DATABASE_PREFIX = "agentdeck-relay-test-companion-w0";
const STORE_NAME = "durable";
const STATE_KEY = "state";
const KEK_KEY = "kek";
const PAIRED_KEY = "paired";
const COUNTER_GUARD_KEY = "counterGuard";
const REVOKED_KEY = "revoked";
const PAIRED_AAD_DOMAIN = "AgentDeck/WebPairedStateV1\0";
const MAX_PAIRED_STATE_BYTES = 256 * 1024;

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
  stateCommitment: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
}>;

type StableCounterGuardRecord = Readonly<{
  key: typeof COUNTER_GUARD_KEY;
  phase: "stable";
  revision: number;
  stateCommitment: Uint8Array;
}>;

type PendingCounterGuardRecord = Readonly<{
  key: typeof COUNTER_GUARD_KEY;
  phase: "pending" | "statePending";
  previousRevision: number;
  previousStateCommitment: Uint8Array;
  nextRevision: number;
  nextStateCommitment: Uint8Array;
  nextIv: Uint8Array;
  nextCiphertext: Uint8Array;
}>;

type QuarantinedCounterGuardRecord = Readonly<{
  key: typeof COUNTER_GUARD_KEY;
  phase: "quarantined";
  reason: "stateFork";
  observedRevision: number;
  observedStateCommitment: Uint8Array;
}>;

type CounterGuardRecord =
  | StableCounterGuardRecord
  | PendingCounterGuardRecord
  | QuarantinedCounterGuardRecord;

export type DurableCommitStage =
  | "guardPendingDurable"
  | "stateGuardPendingDurable"
  | "stateDurable"
  | "guardStableDurable";

export type DurableCommitObserver = (stage: DurableCommitStage) => void | Promise<void>;

type RevokedRecord = Readonly<{
  key: typeof REVOKED_KEY;
  revision: number;
  committedAtMs: number;
}>;

export type PairedStateLoad =
  | Readonly<{
      status: "active";
      revision: number;
      state: Uint8Array;
      reservationRecovery: W3ReservationRecovery;
    }>
  | Readonly<{ status: "revoked"; revision: number }>
  | Readonly<{ status: "missing" }>;

export type PairedStorageEvidence = Readonly<{
  pairedPresent: boolean;
  kekPresent: boolean;
  revokedPresent: boolean;
  revision: number | null;
  ciphertextBytes: number;
}>;

export type W3ReservationRecovery =
  | "pendingPreviousFinalized"
  | "pendingNextFinalized"
  | "statePendingPreviousRetried"
  | "statePendingNextFinalized"
  | "stableExact";

export type W3ReservationStorageEvidence = Readonly<{
  pairedRevision: number | null;
  guardPhase: "pending" | "statePending" | "stable" | "quarantined" | null;
  guardRevision: number | null;
  pendingPreviousRevision: number | null;
  pendingNextRevision: number | null;
  stagedCiphertextBytes: number;
  quarantineReason: "stateFork" | null;
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

type PairedBundle = Readonly<{
  paired: EncryptedPairedRecord | undefined;
  guard: CounterGuardRecord | undefined;
  revoked: RevokedRecord | undefined;
  kek: CryptoKey | undefined;
}>;

type ActiveBundle = Readonly<{
  paired: EncryptedPairedRecord;
  guard: CounterGuardRecord;
  kek: CryptoKey;
}>;

async function withStore<T>(
  profileId: string,
  mode: IDBTransactionMode,
  body: (store: IDBObjectStore) => Promise<T>,
): Promise<T> {
  const database = await openDatabase(profileId);
  const transaction = database.transaction(STORE_NAME, mode);
  const completed = transactionDone(transaction);
  try {
    const result = await body(transaction.objectStore(STORE_NAME));
    await completed;
    return result;
  } catch (error) {
    try {
      transaction.abort();
    } catch {
      // transaction 已完成时无需额外动作。
    }
    await completed.catch(() => undefined);
    throw error;
  } finally {
    database.close();
  }
}

async function readBundle(store: IDBObjectStore): Promise<PairedBundle> {
  const [paired, guard, revoked, kekRecord] = await Promise.all([
    requestResult(store.get(PAIRED_KEY)) as Promise<EncryptedPairedRecord | undefined>,
    requestResult(store.get(COUNTER_GUARD_KEY)) as Promise<CounterGuardRecord | undefined>,
    requestResult(store.get(REVOKED_KEY)) as Promise<RevokedRecord | undefined>,
    requestResult(store.get(KEK_KEY)) as Promise<{ value?: CryptoKey } | undefined>,
  ]);
  return { paired, guard, revoked, kek: kekRecord?.value };
}

async function readPairedBundle(profileId: string): Promise<PairedBundle> {
  return withStore(profileId, "readonly", readBundle);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}

function safeRevision(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function validBytes(value: unknown, size?: number): value is Uint8Array {
  return value instanceof Uint8Array && (size === undefined || value.byteLength === size);
}

function validatePaired(record: EncryptedPairedRecord): void {
  if (
    record.key !== PAIRED_KEY ||
    !safeRevision(record.revision) ||
    !validBytes(record.stateCommitment, 32) ||
    !validBytes(record.iv, 12) ||
    !validBytes(record.ciphertext) ||
    record.ciphertext.byteLength <= 16 ||
    record.ciphertext.byteLength > MAX_PAIRED_STATE_BYTES + 16
  ) {
    throw new Error("web.remote.storage.pairedStateInvalid");
  }
}

function validateGuard(record: CounterGuardRecord): void {
  if (record.key !== COUNTER_GUARD_KEY) {
    throw new Error("web.remote.storage.counterGuardInvalid");
  }
  if (record.phase === "stable") {
    if (!safeRevision(record.revision) || !validBytes(record.stateCommitment, 32)) {
      throw new Error("web.remote.storage.counterGuardInvalid");
    }
    return;
  }
  if (record.phase === "quarantined") {
    if (
      record.reason !== "stateFork" ||
      !safeRevision(record.observedRevision) ||
      !validBytes(record.observedStateCommitment, 32)
    ) {
      throw new Error("web.remote.storage.counterGuardInvalid");
    }
    return;
  }
  if (
    (record.phase !== "pending" && record.phase !== "statePending") ||
    !safeRevision(record.previousRevision) ||
    !safeRevision(record.nextRevision) ||
    record.nextRevision !== record.previousRevision + 1 ||
    !validBytes(record.previousStateCommitment, 32) ||
    !validBytes(record.nextStateCommitment, 32) ||
    equalBytes(record.previousStateCommitment, record.nextStateCommitment) ||
    !validBytes(record.nextIv, 12) ||
    !validBytes(record.nextCiphertext) ||
    record.nextCiphertext.byteLength <= 16 ||
    record.nextCiphertext.byteLength > MAX_PAIRED_STATE_BYTES + 16
  ) {
    throw new Error("web.remote.storage.counterGuardInvalid");
  }
}

function validateRevoked(record: RevokedRecord): void {
  if (
    record.key !== REVOKED_KEY ||
    !safeRevision(record.revision) ||
    !safeRevision(record.committedAtMs)
  ) {
    throw new Error("web.remote.storage.revokedStateInvalid");
  }
}

function activeBundle(bundle: PairedBundle, code: string): ActiveBundle {
  if (
    bundle.revoked !== undefined ||
    bundle.paired === undefined ||
    bundle.guard === undefined ||
    !(bundle.kek instanceof CryptoKey)
  ) {
    throw new Error(code);
  }
  validatePaired(bundle.paired);
  validateGuard(bundle.guard);
  return { paired: bundle.paired, guard: bundle.guard, kek: bundle.kek };
}

function stableMatches(guard: StableCounterGuardRecord, paired: EncryptedPairedRecord): boolean {
  return guard.revision === paired.revision && equalBytes(guard.stateCommitment, paired.stateCommitment);
}

function pendingMatches(
  guard: PendingCounterGuardRecord,
  paired: EncryptedPairedRecord,
  side: "previous" | "next",
): boolean {
  return side === "previous"
    ? guard.previousRevision === paired.revision &&
        equalBytes(guard.previousStateCommitment, paired.stateCommitment)
    : guard.nextRevision === paired.revision &&
        equalBytes(guard.nextStateCommitment, paired.stateCommitment) &&
        equalBytes(guard.nextIv, paired.iv) &&
        equalBytes(guard.nextCiphertext, paired.ciphertext);
}

function isPendingGuard(record: CounterGuardRecord): record is PendingCounterGuardRecord {
  return record.phase === "pending" || record.phase === "statePending";
}

function samePending(left: PendingCounterGuardRecord, right: PendingCounterGuardRecord): boolean {
  return (
    left.phase === right.phase &&
    left.previousRevision === right.previousRevision &&
    left.nextRevision === right.nextRevision &&
    equalBytes(left.previousStateCommitment, right.previousStateCommitment) &&
    equalBytes(left.nextStateCommitment, right.nextStateCommitment) &&
    equalBytes(left.nextIv, right.nextIv) &&
    equalBytes(left.nextCiphertext, right.nextCiphertext)
  );
}

function pairedFromPending(guard: PendingCounterGuardRecord): EncryptedPairedRecord {
  return {
    key: PAIRED_KEY,
    revision: guard.nextRevision,
    stateCommitment: guard.nextStateCommitment,
    iv: guard.nextIv,
    ciphertext: guard.nextCiphertext,
  };
}

function stableFromPending(guard: PendingCounterGuardRecord): StableCounterGuardRecord {
  return {
    key: COUNTER_GUARD_KEY,
    phase: "stable",
    revision: guard.nextRevision,
    stateCommitment: guard.nextStateCommitment,
  };
}

async function commitment(state: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", cryptoBytes(state)));
}

function pairedAad(profileId: string, revision: number, digest: Uint8Array): Uint8Array<ArrayBuffer> {
  const prefix = new TextEncoder().encode(`${PAIRED_AAD_DOMAIN}${profileId}\0${revision}\0`);
  const aad = new Uint8Array(prefix.byteLength + digest.byteLength);
  aad.set(prefix);
  aad.set(digest, prefix.byteLength);
  return aad;
}

async function encryptPairedState(
  profileId: string,
  revision: number,
  state: Uint8Array,
  kek: CryptoKey,
): Promise<EncryptedPairedRecord> {
  if (state.byteLength === 0 || state.byteLength > MAX_PAIRED_STATE_BYTES) {
    throw new Error("web.remote.storage.pairedStateSizeInvalid");
  }
  const stateCommitment = await commitment(state);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: pairedAad(profileId, revision, stateCommitment) },
      kek,
      cryptoBytes(state),
    ),
  );
  return { key: PAIRED_KEY, revision, stateCommitment, iv, ciphertext };
}

async function advancePending(
  profileId: string,
  expected: PendingCounterGuardRecord,
  from: "previous" | "next",
): Promise<void> {
  await withStore(profileId, "readwrite", async (store) => {
    const active = activeBundle(await readBundle(store), "web.remote.storage.counterGuardConflict");
    if (
      !isPendingGuard(active.guard) ||
      !samePending(active.guard, expected) ||
      !pendingMatches(active.guard, active.paired, from)
    ) {
      throw new Error("web.remote.storage.counterGuardFork");
    }
    await requestResult(
      store.put(from === "previous" ? pairedFromPending(active.guard) : stableFromPending(active.guard)),
    );
  });
}

async function beginPendingTransition(
  profileId: string,
  expectedRevision: number,
  encrypted: EncryptedPairedRecord,
  phase: PendingCounterGuardRecord["phase"],
): Promise<PendingCounterGuardRecord> {
  let pending: PendingCounterGuardRecord | null = null;
  await withStore(profileId, "readwrite", async (store) => {
    const active = activeBundle(
      await readBundle(store),
      "web.remote.storage.pairedRevisionConflict",
    );
    if (
      active.paired.revision !== expectedRevision ||
      active.guard.phase !== "stable" ||
      !stableMatches(active.guard, active.paired)
    ) {
      throw new Error("web.remote.storage.pairedRevisionConflict");
    }
    pending = {
      key: COUNTER_GUARD_KEY,
      phase,
      previousRevision: expectedRevision,
      previousStateCommitment: active.paired.stateCommitment,
      nextRevision: encrypted.revision,
      nextStateCommitment: encrypted.stateCommitment,
      nextIv: encrypted.iv,
      nextCiphertext: encrypted.ciphertext,
    };
    await requestResult(store.put(pending));
  });
  if (pending === null) {
    throw new Error("web.remote.storage.counterGuardConflict");
  }
  return pending;
}

export async function promotePairedState(profileId: string, state: Uint8Array): Promise<number> {
  const encrypted = await encryptPairedState(profileId, 0, state, await ensureKek(profileId));
  await withStore(profileId, "readwrite", async (store) => {
    const bundle = await readBundle(store);
    if (bundle.paired !== undefined || bundle.guard !== undefined || bundle.revoked !== undefined) {
      throw new Error("web.remote.storage.pairedPromotionConflict");
    }
    await Promise.all([
      requestResult(store.add(encrypted)),
      requestResult(
        store.add({
          key: COUNTER_GUARD_KEY,
          phase: "stable",
          revision: 0,
          stateCommitment: encrypted.stateCommitment,
        } satisfies StableCounterGuardRecord),
      ),
    ]);
  });
  return 0;
}

export async function commitPairedState(
  profileId: string,
  expectedRevision: number,
  state: Uint8Array,
  observer?: DurableCommitObserver,
): Promise<number> {
  const nextRevision = expectedRevision + 1;
  if (!Number.isSafeInteger(nextRevision) || nextRevision <= expectedRevision) {
    throw new Error("web.remote.storage.revisionInvalid");
  }
  const initial = activeBundle(
    await readPairedBundle(profileId),
    "web.remote.storage.pairedRevisionConflict",
  );
  const encrypted = await encryptPairedState(profileId, nextRevision, state, initial.kek);
  const pending = await beginPendingTransition(profileId, expectedRevision, encrypted, "pending");
  await observer?.("guardPendingDurable");
  await advancePending(profileId, pending, "previous");
  await observer?.("stateDurable");
  await advancePending(profileId, pending, "next");
  await observer?.("guardStableDurable");
  return nextRevision;
}

export async function commitPairedProjectionState(
  profileId: string,
  expectedRevision: number,
  state: Uint8Array,
  observer?: DurableCommitObserver,
): Promise<number> {
  const nextRevision = expectedRevision + 1;
  if (!Number.isSafeInteger(nextRevision) || nextRevision <= expectedRevision) {
    throw new Error("web.remote.storage.revisionInvalid");
  }
  const initial = activeBundle(
    await readPairedBundle(profileId),
    "web.remote.storage.pairedRevisionConflict",
  );
  const encrypted = await encryptPairedState(profileId, nextRevision, state, initial.kek);
  const pending = await beginPendingTransition(
    profileId,
    expectedRevision,
    encrypted,
    "statePending",
  );
  await observer?.("stateGuardPendingDurable");
  await advancePending(profileId, pending, "previous");
  await observer?.("stateDurable");
  await advancePending(profileId, pending, "next");
  await observer?.("guardStableDurable");
  return nextRevision;
}

async function recoverPending(
  profileId: string,
  guard: PendingCounterGuardRecord,
  paired: EncryptedPairedRecord,
): Promise<W3ReservationRecovery> {
  if (pendingMatches(guard, paired, "previous")) {
    await advancePending(profileId, guard, "previous");
    await advancePending(profileId, guard, "next");
    return "pendingPreviousFinalized";
  }
  if (pendingMatches(guard, paired, "next")) {
    await advancePending(profileId, guard, "next");
    return "pendingNextFinalized";
  }
  throw new Error("web.remote.storage.counterGuardFork");
}

async function rollbackStatePending(
  profileId: string,
  expected: PendingCounterGuardRecord,
): Promise<void> {
  await withStore(profileId, "readwrite", async (store) => {
    const active = activeBundle(await readBundle(store), "web.remote.storage.counterGuardConflict");
    if (
      active.guard.phase !== "statePending" ||
      !samePending(active.guard, expected) ||
      !pendingMatches(active.guard, active.paired, "previous")
    ) {
      throw new Error("web.remote.storage.counterGuardFork");
    }
    await requestResult(
      store.put({
        key: COUNTER_GUARD_KEY,
        phase: "stable",
        revision: expected.previousRevision,
        stateCommitment: expected.previousStateCommitment,
      } satisfies StableCounterGuardRecord),
    );
  });
}

async function retryStatePending(
  profileId: string,
  expected: PendingCounterGuardRecord,
): Promise<void> {
  await withStore(profileId, "readwrite", async (store) => {
    const active = activeBundle(await readBundle(store), "web.remote.storage.counterGuardConflict");
    if (
      active.guard.phase !== "stable" ||
      active.guard.revision !== expected.previousRevision ||
      !stableMatches(active.guard, active.paired) ||
      !equalBytes(active.guard.stateCommitment, expected.previousStateCommitment)
    ) {
      throw new Error("web.remote.storage.counterGuardFork");
    }
    await requestResult(store.put(expected));
  });
  await advancePending(profileId, expected, "previous");
  await advancePending(profileId, expected, "next");
}

async function quarantineStateFork(
  profileId: string,
  expected: PendingCounterGuardRecord,
  observed: EncryptedPairedRecord,
): Promise<void> {
  await withStore(profileId, "readwrite", async (store) => {
    const active = activeBundle(await readBundle(store), "web.remote.storage.counterGuardConflict");
    if (
      active.guard.phase !== "statePending" ||
      !samePending(active.guard, expected) ||
      active.paired.revision !== observed.revision ||
      !equalBytes(active.paired.stateCommitment, observed.stateCommitment)
    ) {
      throw new Error("web.remote.storage.counterGuardConflict");
    }
    await requestResult(
      store.put({
        key: COUNTER_GUARD_KEY,
        phase: "quarantined",
        reason: "stateFork",
        observedRevision: observed.revision,
        observedStateCommitment: observed.stateCommitment,
      } satisfies QuarantinedCounterGuardRecord),
    );
  });
}

async function recoverStatePending(
  profileId: string,
  guard: PendingCounterGuardRecord,
  paired: EncryptedPairedRecord,
): Promise<W3ReservationRecovery> {
  if (pendingMatches(guard, paired, "previous")) {
    await rollbackStatePending(profileId, guard);
    await retryStatePending(profileId, guard);
    return "statePendingPreviousRetried";
  }
  if (pendingMatches(guard, paired, "next")) {
    await advancePending(profileId, guard, "next");
    return "statePendingNextFinalized";
  }
  await quarantineStateFork(profileId, guard, paired);
  throw new Error("web.remote.storage.state_fork_quarantined");
}

export async function loadPairedState(profileId: string): Promise<PairedStateLoad> {
  let bundle = await readPairedBundle(profileId);
  if (bundle.revoked !== undefined) {
    validateRevoked(bundle.revoked);
    if (bundle.paired !== undefined || bundle.guard !== undefined || bundle.kek !== undefined) {
      throw new Error("web.remote.storage.revokedMaterialPresent");
    }
    return { status: "revoked", revision: bundle.revoked.revision };
  }
  if (bundle.paired === undefined && bundle.guard === undefined && bundle.kek === undefined) {
    return { status: "missing" };
  }
  let active = activeBundle(bundle, "web.remote.storage.pairedStateIncomplete");
  let reservationRecovery: W3ReservationRecovery = "stableExact";
  if (active.guard.phase === "pending") {
    reservationRecovery = await recoverPending(profileId, active.guard, active.paired);
    bundle = await readPairedBundle(profileId);
    active = activeBundle(bundle, "web.remote.storage.counterGuardRecoveryFailed");
  } else if (active.guard.phase === "statePending") {
    reservationRecovery = await recoverStatePending(profileId, active.guard, active.paired);
    bundle = await readPairedBundle(profileId);
    active = activeBundle(bundle, "web.remote.storage.counterGuardRecoveryFailed");
  } else if (active.guard.phase === "quarantined") {
    throw new Error("web.remote.storage.state_quarantined");
  }
  if (active.guard.phase !== "stable" || !stableMatches(active.guard, active.paired)) {
    throw new Error("web.remote.storage.counterGuardFork");
  }
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: cryptoBytes(active.paired.iv),
        additionalData: pairedAad(
          profileId,
          active.paired.revision,
          active.paired.stateCommitment,
        ),
      },
      active.kek,
      cryptoBytes(active.paired.ciphertext),
    ),
  );
  if (!equalBytes(await commitment(plaintext), active.paired.stateCommitment)) {
    throw new Error("web.remote.storage.pairedCommitmentMismatch");
  }
  return {
    status: "active",
    revision: active.paired.revision,
    state: plaintext,
    reservationRecovery,
  };
}

export async function injectStateSiblingForTest(
  profileId: string,
  state: Uint8Array,
): Promise<void> {
  const initial = activeBundle(
    await readPairedBundle(profileId),
    "web.remote.storage.counterGuardConflict",
  );
  if (initial.guard.phase !== "statePending") {
    throw new Error("web.remote.storage.counterGuardConflict");
  }
  const expectedGuard = initial.guard;
  const sibling = await encryptPairedState(
    profileId,
    expectedGuard.nextRevision,
    state,
    initial.kek,
  );
  await withStore(profileId, "readwrite", async (store) => {
    const active = activeBundle(await readBundle(store), "web.remote.storage.counterGuardConflict");
    if (
      active.guard.phase !== "statePending" ||
      !samePending(active.guard, expectedGuard) ||
      !pendingMatches(active.guard, active.paired, "previous")
    ) {
      throw new Error("web.remote.storage.counterGuardConflict");
    }
    await requestResult(store.put(sibling));
  });
}

export async function commitRevokedCleanup(
  profileId: string,
  expectedRevision: number,
): Promise<number> {
  const nextRevision = expectedRevision + 1;
  await withStore(profileId, "readwrite", async (store) => {
    const active = activeBundle(await readBundle(store), "web.remote.storage.revocationConflict");
    if (
      active.paired.revision !== expectedRevision ||
      active.guard.phase !== "stable" ||
      !stableMatches(active.guard, active.paired)
    ) {
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
    await requestResult(store.delete(COUNTER_GUARD_KEY));
    await requestResult(store.delete(KEK_KEY));
  });
  return nextRevision;
}

export async function inspectReservationStorage(
  profileId: string,
): Promise<W3ReservationStorageEvidence> {
  const { paired, guard, revoked } = await readPairedBundle(profileId);
  if (paired !== undefined) {
    validatePaired(paired);
  }
  if (guard !== undefined) {
    validateGuard(guard);
  }
  if (revoked !== undefined) {
    validateRevoked(revoked);
  }
  return {
    pairedRevision: paired?.revision ?? null,
    guardPhase: guard?.phase ?? null,
    guardRevision: guard?.phase === "stable" ? guard.revision : null,
    pendingPreviousRevision: guard !== undefined && isPendingGuard(guard) ? guard.previousRevision : null,
    pendingNextRevision: guard !== undefined && isPendingGuard(guard) ? guard.nextRevision : null,
    stagedCiphertextBytes:
      guard !== undefined && isPendingGuard(guard) ? guard.nextCiphertext.byteLength : 0,
    quarantineReason: guard?.phase === "quarantined" ? guard.reason : null,
  };
}

export async function inspectPairedStorage(profileId: string): Promise<PairedStorageEvidence> {
  const { paired, kek, revoked } = await readPairedBundle(profileId);
  if (paired !== undefined) {
    validatePaired(paired);
  }
  if (revoked !== undefined) {
    validateRevoked(revoked);
  }
  return {
    pairedPresent: paired !== undefined,
    kekPresent: kek !== undefined,
    revokedPresent: revoked !== undefined,
    revision: paired?.revision ?? revoked?.revision ?? null,
    ciphertextBytes: paired?.ciphertext.byteLength ?? 0,
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
