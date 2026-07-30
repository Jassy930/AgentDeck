export type RevisionTransition = Readonly<{
  actualRevision: number;
  expectedRevision: number;
  nextRevision: number;
}>;

export function assertExactRevisionTransition(transition: RevisionTransition): void {
  const { actualRevision, expectedRevision, nextRevision } = transition;
  if (!Number.isSafeInteger(actualRevision) || actualRevision < 0) {
    throw new Error("web.remote.storage.invalidActualRevision");
  }
  if (actualRevision !== expectedRevision) {
    throw new Error("web.remote.storage.revisionConflict");
  }
  if (nextRevision !== expectedRevision + 1) {
    throw new Error("web.remote.storage.nonExactNextRevision");
  }
}
