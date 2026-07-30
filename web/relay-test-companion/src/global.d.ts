declare global {
  type W1TransportCase =
    | "positive"
    | "wrongServer"
    | "tamperChallenge"
    | "tamperSignature"
    | "replayAuthenticate"
    | "textFrame"
    | "oversizeFrame"
    | "disconnect"
    | "unavailable";

  type W1TransportEvidence = Readonly<{
    caseName: W1TransportCase;
    generation: number;
    authenticated: boolean;
    sentinelAccepted: boolean;
    binaryFramesSent: number;
    failureCode: string | null;
  }>;

  type DurableStateRecord = Readonly<{
    key: string;
    revision: number;
    payload: string;
  }>;

  type W2PairingPreview = Readonly<{
    machineDisplayName: string;
    machineRootFingerprint: string;
  }>;

  type W2PairingEvidence = Readonly<{
    fingerprintConfirmed: boolean;
    authenticated: boolean;
    pendingObserved: boolean;
    responseVerified: boolean;
    receiptSent: boolean;
    routeAcceptedObserved: boolean;
    paired: boolean;
    machineRoutePresent: boolean;
    deviceRoutePresent: boolean;
  }>;

  type W2TransportEvidence = Readonly<{
    generation: number;
    preview: W2PairingPreview;
    preConfirmNetworkLocked: boolean;
    binaryFramesSent: number;
    pairing: W2PairingEvidence;
    failureCode: string | null;
  }>;

  type W2BusinessEvidence = Readonly<{
    principalAuthenticated: boolean;
    catalogRouteAccepted: boolean;
    catalogEntryCount: number;
    conversationTitle: string | null;
    catalogSubscriptionActive: boolean;
    businessFenceCount: number;
    conversationRouteAccepted: boolean;
    conversationOpen: boolean;
    relaySubscriptionActive: boolean;
    promptRouteAccepted: boolean;
    promptAccepted: boolean;
    assistantObserved: boolean;
    approvalPending: boolean;
    approvalSummaryMatched: boolean;
    approvalRouteAccepted: boolean;
    approvalReceiptApplied: boolean;
    approvalEventApplied: boolean;
    commandCompleted: boolean;
    outerAckCount: number;
    durablePromoted: boolean;
    durableRestored: boolean;
    counterReservationStart: number;
    counterReservationEnd: number;
    reconnectAuthenticated: boolean;
    recoveryCatalogBackfillCount: number;
    recoveryConversationBackfillCount: number;
    restartMarkerObserved: boolean;
    revokeRouteAccepted: boolean;
    revocationReceiptCommitted: boolean;
    revocationTerminalVerified: boolean;
    recoveryStage: string | null;
  }>;

  type W2NegativeEvidence = Readonly<{
    approvalLoserRecognizedApplied: boolean;
    approvalLoserZeroClaimMutation: boolean;
    stalePublishRejected: boolean;
    skippedPublishRejected: boolean;
    rejectedPublishCursorUnchanged: boolean;
    replyNonceReplayRejected: boolean;
    replyCounterSetUnchanged: boolean;
    streamNonceReuseRejected: boolean;
    streamCounterSetUnchanged: boolean;
    uncommittedReservationRejected: boolean;
    reservationOverflowRejected: boolean;
    rejectedReservationCounterUnchanged: boolean;
  }>;

  type PairedStorageEvidence = Readonly<{
    pairedPresent: boolean;
    kekPresent: boolean;
    revokedPresent: boolean;
    revision: number | null;
    ciphertextBytes: number;
  }>;

  type W2DurableStartEvidence = Readonly<{
    generation: number;
    revision: number | null;
    pairing: W2PairingEvidence;
    business: W2BusinessEvidence | null;
    storage: PairedStorageEvidence;
    failureCode: string | null;
  }>;

  type W2DurableRecoveryEvidence = Readonly<{
    generation: number;
    revision: number | null;
    preActivationNetworkLocked: boolean;
    business: W2BusinessEvidence | null;
    binaryFramesSent: number;
    storage: PairedStorageEvidence;
    reloadStatus: "active" | "revoked" | "missing";
    reservationRecovery: W3ReservationRecovery | null;
    failureCode: string | null;
  }>;

  type W3CrashCut =
    | "guardPendingDurable"
    | "stateDurable"
    | "guardStableDurable";

  type W3ReservationRecovery =
    | "pendingPreviousFinalized"
    | "pendingNextFinalized"
    | "stableExact";

  type W3ReservationStorageEvidence = Readonly<{
    pairedRevision: number | null;
    guardPhase: "pending" | "stable" | null;
    guardRevision: number | null;
    pendingPreviousRevision: number | null;
    pendingNextRevision: number | null;
    stagedCiphertextBytes: number;
  }>;

  type W3CrashCutEvidence = Readonly<{
    cut: W3CrashCut;
    revisionBefore: number;
    faultInjected: boolean;
    binaryFramesSent: 0;
    storage: W3ReservationStorageEvidence;
    failureCode: string | null;
  }>;

  type W2BusinessTransportEvidence = Readonly<{
    generation: number;
    preview: W2PairingPreview;
    preConfirmNetworkLocked: boolean;
    binaryFramesSent: number;
    pairingBinaryFramesSent: number;
    businessBinaryFramesSent: number;
    pairing: W2PairingEvidence;
    business: W2BusinessEvidence | null;
    failureCode: string | null;
  }>;

  type RelayTestApi = Readonly<{
    contractSnapshot: () => Promise<Record<string, string>>;
    negativeSnapshot: () => Promise<Record<string, boolean>>;
    relayHello: () => Promise<number[]>;
    relayFrameRejected: (input: readonly number[]) => Promise<boolean>;
    runtimeRoundtrip: (input: readonly number[]) => Promise<number[]>;
    runtimeRejected: (input: readonly number[]) => Promise<boolean>;
    cryptoTamperRejected: () => Promise<boolean>;
    w2NegativeSnapshot: () => Promise<W2NegativeEvidence>;
    runW1Transport: (
      origin: string,
      relayServerIdHex: string,
      caseName: W1TransportCase,
    ) => Promise<W1TransportEvidence>;
    runW2Pairing: (encodedInvite: string) => Promise<W2TransportEvidence>;
    runW2Business: (encodedInvite: string) => Promise<W2BusinessTransportEvidence>;
    runW2DurableStart: (
      encodedInvite: string,
      profileId: string,
    ) => Promise<W2DurableStartEvidence>;
    runW2DurableRecover: (profileId: string) => Promise<W2DurableRecoveryEvidence>;
    runW3ReservationCrash: (
      profileId: string,
      cut: W3CrashCut,
    ) => Promise<W3CrashCutEvidence>;
    initializeState: (profileId: string, payload: string) => Promise<DurableStateRecord>;
    readState: (profileId: string) => Promise<DurableStateRecord | null>;
    commitExactRevision: (
      profileId: string,
      expectedRevision: number,
      nextRevision: number,
      payload: string,
      abortAfterPut?: boolean,
    ) => Promise<DurableStateRecord>;
    createAndProveNonExtractableKek: (profileId: string) => Promise<{
      algorithm: string;
      extractable: boolean;
      roundtrip: boolean;
      exportRejected: boolean;
    }>;
    acquireWriter: (profileId: string) => Promise<boolean>;
    releaseWriter: (profileId: string) => Promise<void>;
    deleteProfile: (profileId: string) => Promise<void>;
  }>;

  var relayTestApi: RelayTestApi;
}

export {};
