import { describe, expect, test } from "bun:test";

import { assertExactRevisionTransition } from "../../src/revision.ts";

describe("W0 exact revision contract", () => {
  test("accepts only exact next revision", () => {
    expect(() =>
      assertExactRevisionTransition({ actualRevision: 7, expectedRevision: 7, nextRevision: 8 }),
    ).not.toThrow();
  });

  test("rejects stale sibling and skipped revision", () => {
    expect(() =>
      assertExactRevisionTransition({ actualRevision: 8, expectedRevision: 7, nextRevision: 8 }),
    ).toThrow("web.remote.storage.revisionConflict");
    expect(() =>
      assertExactRevisionTransition({ actualRevision: 8, expectedRevision: 8, nextRevision: 10 }),
    ).toThrow("web.remote.storage.nonExactNextRevision");
  });
});
