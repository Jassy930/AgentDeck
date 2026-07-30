import { acquireWriterLease, type WriterLease } from "./storage.ts";

const CHANNEL_PREFIX = "agentdeck-relay-test-companion-generation";

type GenerationAnnouncement = Readonly<{
  schemaVersion: 1;
  kind: "writer-active";
  token: string;
}>;

export type WriterGenerationSnapshot = Readonly<{
  acquired: boolean;
  relinquished: boolean;
  invalidatedByPeer: boolean;
  closed: boolean;
}>;

export type WriterGeneration = Readonly<{
  acquired: boolean;
  assertCurrent: () => void;
  snapshot: () => WriterGenerationSnapshot;
  relinquish: () => Promise<void>;
  close: () => Promise<void>;
}>;

function isAnnouncement(value: unknown): value is GenerationAnnouncement {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Partial<GenerationAnnouncement>;
  return (
    candidate.schemaVersion === 1 &&
    candidate.kind === "writer-active" &&
    typeof candidate.token === "string" &&
    candidate.token.length >= 16 &&
    candidate.token.length <= 128
  );
}

function unavailableGeneration(writer: WriterLease): WriterGeneration {
  let closed = false;
  return {
    acquired: false,
    assertCurrent() {
      throw new Error("web.remote.writer_locked");
    },
    snapshot() {
      return {
        acquired: false,
        relinquished: false,
        invalidatedByPeer: false,
        closed,
      };
    },
    async relinquish() {
      await writer.release();
    },
    async close() {
      if (!closed) {
        closed = true;
        await writer.release();
      }
    },
  };
}

export async function acquireWriterGeneration(profileId: string): Promise<WriterGeneration> {
  const writer = await acquireWriterLease(profileId);
  if (!writer.acquired) {
    return unavailableGeneration(writer);
  }

  const token = crypto.randomUUID();
  const channel = new BroadcastChannel(`${CHANNEL_PREFIX}-${profileId}`);
  let relinquished = false;
  let invalidatedByPeer = false;
  let closed = false;

  channel.addEventListener("message", (event: MessageEvent<unknown>) => {
    if (isAnnouncement(event.data) && event.data.token !== token) {
      invalidatedByPeer = true;
    }
  });
  channel.postMessage({
    schemaVersion: 1,
    kind: "writer-active",
    token,
  } satisfies GenerationAnnouncement);

  const assertCurrent = (): void => {
    if (relinquished || invalidatedByPeer || closed) {
      throw new Error("web.remote.generation_stale");
    }
  };
  const relinquish = async (): Promise<void> => {
    if (!relinquished) {
      relinquished = true;
      await writer.release();
    }
  };

  return {
    acquired: true,
    assertCurrent,
    snapshot() {
      return {
        acquired: true,
        relinquished,
        invalidatedByPeer,
        closed,
      };
    },
    relinquish,
    async close() {
      if (!closed) {
        await relinquish();
        closed = true;
        channel.close();
      }
    },
  };
}
