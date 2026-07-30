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

  type RelayTestApi = Readonly<{
    contractSnapshot: () => Promise<Record<string, string>>;
    negativeSnapshot: () => Promise<Record<string, boolean>>;
    relayHello: () => Promise<number[]>;
    relayFrameRejected: (input: readonly number[]) => Promise<boolean>;
    runtimeRoundtrip: (input: readonly number[]) => Promise<number[]>;
    runtimeRejected: (input: readonly number[]) => Promise<boolean>;
    cryptoTamperRejected: () => Promise<boolean>;
    runW1Transport: (
      origin: string,
      relayServerIdHex: string,
      caseName: W1TransportCase,
    ) => Promise<W1TransportEvidence>;
    runW2Pairing: (encodedInvite: string) => Promise<W2TransportEvidence>;
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
