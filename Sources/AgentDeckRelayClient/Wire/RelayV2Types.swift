import Foundation

public let relayProtocolVersionV2: UInt16 = 2

public enum RelayWireCodecError: Error, Equatable, Sendable {
    case oversize
    case shortInput
    case badMagic
    case unsupportedVersion(UInt16)
    case unknownKind(UInt16)
    case lengthOutOfBounds
    case trailingBytes
    case invalidEnumTag(UInt8)
    case invalidUTF8
    case invalidLength(field: String, expected: Int, actual: Int)
    case invalidVersion(field: String, expected: UInt16, actual: UInt16)
    case unknownField(String)
}

public struct RelayV2Hello: Codable, Equatable, Sendable {
    public let protocolVersion: UInt16

    public init(protocolVersion: UInt16) {
        self.protocolVersion = protocolVersion
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case protocolVersion
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        protocolVersion = try decoder.container(keyedBy: CodingKeys.self)
            .decode(UInt16.self, forKey: .protocolVersion)
    }
}

public enum RelayV2CertRole: String, Codable, Equatable, Sendable {
    case link
    case data
}

public struct RelayV2SignedCertificate: Codable, Equatable, Sendable {
    public var subjectPubkey: Data
    public var certRole: RelayV2CertRole
    public var generation: UInt64
    public var rootKeyId: Data
    public var trustEpoch: UInt64
    public var notAfterMs: UInt64?
    public var signature: Data

    public init(
        subjectPubkey: Data,
        certRole: RelayV2CertRole,
        generation: UInt64,
        rootKeyId: Data,
        trustEpoch: UInt64,
        notAfterMs: UInt64?,
        signature: Data
    ) {
        self.subjectPubkey = subjectPubkey
        self.certRole = certRole
        self.generation = generation
        self.rootKeyId = rootKeyId
        self.trustEpoch = trustEpoch
        self.notAfterMs = notAfterMs
        self.signature = signature
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case subjectPubkey, certRole, generation, rootKeyId, trustEpoch, notAfterMs, signature
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        subjectPubkey = try container.decode(Data.self, forKey: .subjectPubkey)
        certRole = try container.decode(RelayV2CertRole.self, forKey: .certRole)
        generation = try container.decode(UInt64.self, forKey: .generation)
        rootKeyId = try container.decode(Data.self, forKey: .rootKeyId)
        trustEpoch = try container.decode(UInt64.self, forKey: .trustEpoch)
        notAfterMs = try container.decodeIfPresent(UInt64.self, forKey: .notAfterMs)
        signature = try container.decode(Data.self, forKey: .signature)
    }
}

public struct RelayV2Grant: Codable, Equatable, Sendable {
    public var machineRoute: Data
    public var deviceRoute: Data
    public var deviceSignPubkey: Data
    public var grantSerial: UInt64
    public var rootKeyId: Data
    public var trustEpoch: UInt64
    public var signature: Data

    public init(
        machineRoute: Data,
        deviceRoute: Data,
        deviceSignPubkey: Data,
        grantSerial: UInt64,
        rootKeyId: Data,
        trustEpoch: UInt64,
        signature: Data
    ) {
        self.machineRoute = machineRoute
        self.deviceRoute = deviceRoute
        self.deviceSignPubkey = deviceSignPubkey
        self.grantSerial = grantSerial
        self.rootKeyId = rootKeyId
        self.trustEpoch = trustEpoch
        self.signature = signature
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case machineRoute, deviceRoute, deviceSignPubkey, grantSerial
        case rootKeyId, trustEpoch, signature
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        machineRoute = try container.decode(Data.self, forKey: .machineRoute)
        deviceRoute = try container.decode(Data.self, forKey: .deviceRoute)
        deviceSignPubkey = try container.decode(Data.self, forKey: .deviceSignPubkey)
        grantSerial = try container.decode(UInt64.self, forKey: .grantSerial)
        rootKeyId = try container.decode(Data.self, forKey: .rootKeyId)
        trustEpoch = try container.decode(UInt64.self, forKey: .trustEpoch)
        signature = try container.decode(Data.self, forKey: .signature)
    }
}

public struct RelayV2DeviceRevocation: Codable, Equatable, Sendable {
    public var machineRoute: Data
    public var deviceRoute: Data
    public var grantSerial: UInt64
    public var rootKeyId: Data
    public var trustEpoch: UInt64
    public var signature: Data

    public init(
        machineRoute: Data,
        deviceRoute: Data,
        grantSerial: UInt64,
        rootKeyId: Data,
        trustEpoch: UInt64,
        signature: Data
    ) {
        self.machineRoute = machineRoute
        self.deviceRoute = deviceRoute
        self.grantSerial = grantSerial
        self.rootKeyId = rootKeyId
        self.trustEpoch = trustEpoch
        self.signature = signature
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case machineRoute, deviceRoute, grantSerial, rootKeyId, trustEpoch, signature
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        machineRoute = try container.decode(Data.self, forKey: .machineRoute)
        deviceRoute = try container.decode(Data.self, forKey: .deviceRoute)
        grantSerial = try container.decode(UInt64.self, forKey: .grantSerial)
        rootKeyId = try container.decode(Data.self, forKey: .rootKeyId)
        trustEpoch = try container.decode(UInt64.self, forKey: .trustEpoch)
        signature = try container.decode(Data.self, forKey: .signature)
    }
}

public enum RelayV2AuthProof: Codable, Equatable, Sendable {
    case machineLink(machineRoute: Data, linkCert: RelayV2SignedCertificate)
    case device(relayGrant: RelayV2Grant)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RelayJSONCodingKey.self)
        guard container.allKeys.count == 1, let variant = container.allKeys.first else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "AuthProof needs one variant")
            )
        }
        switch variant.stringValue {
        case "machineLink":
            let nestedDecoder = try container.superDecoder(forKey: variant)
            try rejectRelayUnknownKeys(
                nestedDecoder,
                allowed: ["machine_route", "link_cert"]
            )
            let value = try container.decode(MachineLinkProofWire.self, forKey: variant)
            self = .machineLink(machineRoute: value.machine_route, linkCert: value.link_cert)
        case "device":
            let nestedDecoder = try container.superDecoder(forKey: variant)
            try rejectRelayUnknownKeys(nestedDecoder, allowed: ["relay_grant"])
            let value = try container.decode(DeviceProofWire.self, forKey: variant)
            self = .device(relayGrant: value.relay_grant)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: variant,
                in: container,
                debugDescription: "unknown AuthProof variant \(variant.stringValue)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RelayJSONCodingKey.self)
        switch self {
        case .machineLink(let machineRoute, let linkCert):
            try container.encode(
                MachineLinkProofWire(machine_route: machineRoute, link_cert: linkCert),
                forKey: relayKey("machineLink")
            )
        case .device(let relayGrant):
            try container.encode(
                DeviceProofWire(relay_grant: relayGrant),
                forKey: relayKey("device")
            )
        }
    }
}

public enum RelayV2PairRouteCloseOutcome: String, Codable, Equatable, Sendable {
    case closed
    case alreadyAbsent
}

public enum RelayV2AcceptedRef: Codable, Equatable, Sendable {
    case request(requestRoute: Data)
    case streamFrame(streamRoute: Data, streamSeq: UInt64)
    case pairFrame(pairRoute: Data)

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RelayJSONCodingKey.self)
        guard container.allKeys.count == 1, let variant = container.allKeys.first else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "AcceptedRef needs one variant")
            )
        }
        switch variant.stringValue {
        case "request":
            try rejectRelayUnknownKeys(
                container.superDecoder(forKey: variant),
                allowed: ["request_route"]
            )
            let value = try container.decode(RequestAcceptedWire.self, forKey: variant)
            self = .request(requestRoute: value.request_route)
        case "streamFrame":
            try rejectRelayUnknownKeys(
                container.superDecoder(forKey: variant),
                allowed: ["stream_route", "stream_seq"]
            )
            let value = try container.decode(StreamAcceptedWire.self, forKey: variant)
            self = .streamFrame(streamRoute: value.stream_route, streamSeq: value.stream_seq)
        case "pairFrame":
            try rejectRelayUnknownKeys(
                container.superDecoder(forKey: variant),
                allowed: ["pair_route"]
            )
            let value = try container.decode(PairAcceptedWire.self, forKey: variant)
            self = .pairFrame(pairRoute: value.pair_route)
        default:
            throw DecodingError.dataCorruptedError(
                forKey: variant,
                in: container,
                debugDescription: "unknown AcceptedRef variant \(variant.stringValue)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: RelayJSONCodingKey.self)
        switch self {
        case .request(let requestRoute):
            try container.encode(
                RequestAcceptedWire(request_route: requestRoute),
                forKey: relayKey("request")
            )
        case .streamFrame(let streamRoute, let streamSeq):
            try container.encode(
                StreamAcceptedWire(stream_route: streamRoute, stream_seq: streamSeq),
                forKey: relayKey("streamFrame")
            )
        case .pairFrame(let pairRoute):
            try container.encode(
                PairAcceptedWire(pair_route: pairRoute),
                forKey: relayKey("pairFrame")
            )
        }
    }
}

public struct RelayV2Failure: Codable, Equatable, Sendable {
    public var code: String
    public var message: String
    public var inReplyTo: String?

    public init(code: String, message: String, inReplyTo: String? = nil) {
        self.code = code
        self.message = message
        self.inReplyTo = inReplyTo
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case code, message, inReplyTo
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        code = try container.decode(String.self, forKey: .code)
        message = try container.decode(String.self, forKey: .message)
        inReplyTo = try container.decodeIfPresent(String.self, forKey: .inReplyTo)
    }
}

public enum RelayEndpointWireType: String, Sendable {
    case pairInvite = "PairInviteV1"
    case pairRequest = "PairRequestV1"
    case pairResponse = "PairResponseV1"
    case deviceAuthorization = "DeviceAuthorizationV1"
    case keyDirectory = "KeyDirectoryV1"
    case keyUpdate = "KeyUpdateV1"
    case epochBarrier = "EpochBarrierV1"
    case sealedPayload = "SealedPayloadV1"
}

public struct RelayPairInviteV1: Codable, Sendable {
    public var formatVersion: UInt16
    public var relayProtocolVersion: UInt16
    public var pairRoute: Data
    public var inviteSecret: Data
    public var inviteHpkePubkey: Data
    public var wssUrl: String
    public var relayServerId: Data
    public var currentSpkiPin: Data
    public var nextSpkiPin: Data
    public var expiresAtMs: UInt64
    public var machineRootPubkey: Data
    public var machineRootFingerprint: Data
    public var dataSignCert: RelayV2SignedCertificate
    public var machineDisplayName: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case formatVersion, relayProtocolVersion, pairRoute, inviteSecret, inviteHpkePubkey
        case wssUrl, relayServerId, currentSpkiPin, nextSpkiPin, expiresAtMs
        case machineRootPubkey, machineRootFingerprint, dataSignCert, machineDisplayName
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        formatVersion = try container.decode(UInt16.self, forKey: .formatVersion)
        relayProtocolVersion = try container.decode(UInt16.self, forKey: .relayProtocolVersion)
        pairRoute = try container.decode(Data.self, forKey: .pairRoute)
        inviteSecret = try container.decode(Data.self, forKey: .inviteSecret)
        inviteHpkePubkey = try container.decode(Data.self, forKey: .inviteHpkePubkey)
        wssUrl = try container.decode(String.self, forKey: .wssUrl)
        relayServerId = try container.decode(Data.self, forKey: .relayServerId)
        currentSpkiPin = try container.decode(Data.self, forKey: .currentSpkiPin)
        nextSpkiPin = try container.decode(Data.self, forKey: .nextSpkiPin)
        expiresAtMs = try container.decode(UInt64.self, forKey: .expiresAtMs)
        machineRootPubkey = try container.decode(Data.self, forKey: .machineRootPubkey)
        machineRootFingerprint = try container.decode(Data.self, forKey: .machineRootFingerprint)
        dataSignCert = try container.decode(RelayV2SignedCertificate.self, forKey: .dataSignCert)
        machineDisplayName = try container.decode(String.self, forKey: .machineDisplayName)
    }
}

public struct RelayPairRequestV1: Codable, Sendable {
    public var formatVersion: UInt16
    public var inviteSecret: Data
    public var deviceSignPubkey: Data
    public var deviceHpkePubkey: Data
    public var sealedAuthorizationRequest: Data
    public var proofSignature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case formatVersion, inviteSecret, deviceSignPubkey, deviceHpkePubkey
        case sealedAuthorizationRequest, proofSignature
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        formatVersion = try container.decode(UInt16.self, forKey: .formatVersion)
        inviteSecret = try container.decode(Data.self, forKey: .inviteSecret)
        deviceSignPubkey = try container.decode(Data.self, forKey: .deviceSignPubkey)
        deviceHpkePubkey = try container.decode(Data.self, forKey: .deviceHpkePubkey)
        sealedAuthorizationRequest = try container.decode(
            Data.self,
            forKey: .sealedAuthorizationRequest
        )
        proofSignature = try container.decode(Data.self, forKey: .proofSignature)
    }
}

public struct RelayDeviceAuthorizationV1: Codable, Sendable {
    public var grantSerial: UInt64
    public var deviceHpkePubkey: Data
    public var capabilities: [String]
    public var permissions: [String]
    public var rootKeyId: Data
    public var trustEpoch: UInt64
    public var signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case grantSerial, deviceHpkePubkey, capabilities, permissions
        case rootKeyId, trustEpoch, signature
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        grantSerial = try container.decode(UInt64.self, forKey: .grantSerial)
        deviceHpkePubkey = try container.decode(Data.self, forKey: .deviceHpkePubkey)
        capabilities = try container.decode([String].self, forKey: .capabilities)
        permissions = try container.decode([String].self, forKey: .permissions)
        rootKeyId = try container.decode(Data.self, forKey: .rootKeyId)
        trustEpoch = try container.decode(UInt64.self, forKey: .trustEpoch)
        signature = try container.decode(Data.self, forKey: .signature)
    }
}

public struct RelayKeyDirectoryEntryV1: Codable, Sendable {
    public var keyId: KeyIDV1
    public var deviceRoute: Data
    public var enc: Data
    public var wrappedKey: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case keyId, deviceRoute, enc, wrappedKey
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        keyId = try container.decode(KeyIDV1.self, forKey: .keyId)
        deviceRoute = try container.decode(Data.self, forKey: .deviceRoute)
        enc = try container.decode(Data.self, forKey: .enc)
        wrappedKey = try container.decode(Data.self, forKey: .wrappedKey)
    }
}

public struct RelayKeyDirectoryV1: Codable, Sendable {
    public var revision: UInt64
    public var entries: [RelayKeyDirectoryEntryV1]
    public var signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case revision, entries, signature
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        revision = try container.decode(UInt64.self, forKey: .revision)
        entries = try container.decode([RelayKeyDirectoryEntryV1].self, forKey: .entries)
        signature = try container.decode(Data.self, forKey: .signature)
    }
}

public struct RelayPairResponseV1: Codable, Sendable {
    public var requestHash: Data
    public var relayGrant: RelayV2Grant
    public var sealedDeviceAuthorization: Data
    public var keyDirectory: RelayKeyDirectoryV1
    public var signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case requestHash, relayGrant, sealedDeviceAuthorization, keyDirectory, signature
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        requestHash = try container.decode(Data.self, forKey: .requestHash)
        relayGrant = try container.decode(RelayV2Grant.self, forKey: .relayGrant)
        sealedDeviceAuthorization = try container.decode(
            Data.self,
            forKey: .sealedDeviceAuthorization
        )
        keyDirectory = try container.decode(RelayKeyDirectoryV1.self, forKey: .keyDirectory)
        signature = try container.decode(Data.self, forKey: .signature)
    }
}

public struct RelayKeyUpdateV1: Codable, Sendable {
    public var keyDirectoryRevision: UInt64
    public var keyId: KeyIDV1
    public var deviceRoute: Data
    public var enc: Data
    public var wrappedKey: Data
    public var signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case keyDirectoryRevision, keyId, deviceRoute, enc, wrappedKey, signature
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        keyDirectoryRevision = try container.decode(UInt64.self, forKey: .keyDirectoryRevision)
        keyId = try container.decode(KeyIDV1.self, forKey: .keyId)
        deviceRoute = try container.decode(Data.self, forKey: .deviceRoute)
        enc = try container.decode(Data.self, forKey: .enc)
        wrappedKey = try container.decode(Data.self, forKey: .wrappedKey)
        signature = try container.decode(Data.self, forKey: .signature)
    }
}

public struct RelayEpochBarrierV1: Codable, Sendable {
    public var streamGeneration: Data
    public var streamCursor: StreamCursor
    public var eventSeq: UInt64
    public var oldEpoch: UInt64
    public var newEpoch: UInt64
    public var keyDirectoryRevision: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case streamGeneration, streamCursor, eventSeq, oldEpoch, newEpoch, keyDirectoryRevision
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        streamGeneration = try container.decode(Data.self, forKey: .streamGeneration)
        streamCursor = try container.decode(StreamCursor.self, forKey: .streamCursor)
        eventSeq = try container.decode(UInt64.self, forKey: .eventSeq)
        oldEpoch = try container.decode(UInt64.self, forKey: .oldEpoch)
        newEpoch = try container.decode(UInt64.self, forKey: .newEpoch)
        keyDirectoryRevision = try container.decode(UInt64.self, forKey: .keyDirectoryRevision)
    }
}

public struct RelaySealedPayloadV1: Codable, Sendable {
    public var formatVersion: UInt16
    public var payloadKind: SealedPayloadKind

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case formatVersion, payloadKind
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        formatVersion = try container.decode(UInt16.self, forKey: .formatVersion)
        payloadKind = try container.decode(SealedPayloadKind.self, forKey: .payloadKind)
    }
}

public enum RelayEndpointPayloadV1: Sendable {
    case pairInvite(RelayPairInviteV1)
    case pairRequest(RelayPairRequestV1)
    case pairResponse(RelayPairResponseV1)
    case deviceAuthorization(RelayDeviceAuthorizationV1)
    case keyDirectory(RelayKeyDirectoryV1)
    case keyUpdate(RelayKeyUpdateV1)
    case epochBarrier(RelayEpochBarrierV1)
    case sealedPayload(RelaySealedPayloadV1)
}

public struct RelayV2Frame: Codable, Equatable, Sendable {
    public let version: UInt16
    public let body: RelayV2FrameBody

    public init(version: UInt16, body: RelayV2FrameBody) {
        self.version = version
        self.body = body
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version, body
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(UInt16.self, forKey: .version)
        body = try container.decode(RelayV2FrameBody.self, forKey: .body)
    }
}

public enum RelayV2FrameBody: Codable, Equatable, Sendable {
    case hello(RelayV2Hello)
    case challenge(relayServerId: Data, connectionInstance: Data, challengeNonce: Data)
    case authenticate(proof: RelayV2AuthProof, signature: Data)
    case authenticated(heartbeatIntervalSecs: UInt16)
    case openPairRoute(machineRoute: Data, pairRoute: Data, absoluteExpiryMs: UInt64)
    case pairRouteOpened(machineRoute: Data, pairRoute: Data, absoluteExpiryMs: UInt64)
    case pairData(pairRoute: Data, sealedBlob: Data)
    case closePairRoute(machineRoute: Data, pairRoute: Data)
    case pairRouteClosed(pairRoute: Data, outcome: RelayV2PairRouteCloseOutcome)
    case registerStream(machineRoute: Data, streamRoute: Data, generation: Data)
    case publish(streamRoute: Data, generation: Data, streamSeq: UInt64, sealedBlob: Data)
    case subscribe(streamRoute: Data, generation: Data, cursor: StreamCursor)
    case unsubscribe(streamRoute: Data, generation: Data)
    case ack(streamRoute: Data, generation: Data, upToSeq: UInt64)
    case gap(streamRoute: Data, generation: Data, needStreamSeq: UInt64, oldestStreamSeq: UInt64)
    case replayComplete(streamRoute: Data, generation: Data, currentCursor: StreamCursor)
    case send(deviceRoute: Data, requestRoute: Data, sealedBlob: Data)
    case reply(deviceRoute: Data, requestRoute: Data, sealedBlob: Data)
    case installGrant(grant: RelayV2Grant)
    case grantCommitted(deviceRoute: Data, grantSerial: UInt64, grantHash: Data)
    case revokeDevice(revocation: RelayV2DeviceRevocation)
    case revocationCommitted(
        deviceRoute: Data,
        grantSerial: UInt64,
        signedRevocation: RelayV2DeviceRevocation
    )
    case retireMachine(machineRoute: Data, trustEpoch: UInt64, signature: Data)
    case ping(nonce: UInt64)
    case pong(nonce: UInt64)
    case routeAccepted(accepted: RelayV2AcceptedRef)
    case error(RelayV2Failure)
    case serverRestarting(drainDeadlineMs: UInt64)

    fileprivate var kind: UInt16 {
        switch self {
        case .hello: 0
        case .challenge: 1
        case .authenticate: 2
        case .authenticated: 3
        case .openPairRoute: 4
        case .pairRouteOpened: 5
        case .pairData: 6
        case .closePairRoute: 7
        case .pairRouteClosed: 8
        case .registerStream: 9
        case .publish: 10
        case .subscribe: 11
        case .unsubscribe: 12
        case .ack: 13
        case .gap: 14
        case .replayComplete: 15
        case .send: 16
        case .reply: 17
        case .installGrant: 18
        case .grantCommitted: 19
        case .revokeDevice: 20
        case .revocationCommitted: 21
        case .retireMachine: 22
        case .ping: 23
        case .pong: 24
        case .routeAccepted: 25
        case .error: 26
        case .serverRestarting: 27
        }
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case frameKind, frame
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let frameKind = try container.decode(String.self, forKey: .frameKind)
        if let allowed = relayFramePayloadKeys[frameKind] {
            try rejectRelayUnknownKeys(
                container.superDecoder(forKey: .frame),
                allowed: allowed
            )
        }
        switch frameKind {
        case "hello": self = .hello(try container.decode(RelayV2Hello.self, forKey: .frame))
        case "challenge":
            let value = try container.decode(ChallengeWire.self, forKey: .frame)
            self = .challenge(
                relayServerId: value.relayServerId,
                connectionInstance: value.connectionInstance,
                challengeNonce: value.challengeNonce
            )
        case "authenticate":
            let value = try container.decode(AuthenticateWire.self, forKey: .frame)
            self = .authenticate(proof: value.proof, signature: value.signature)
        case "authenticated":
            let value = try container.decode(AuthenticatedWire.self, forKey: .frame)
            self = .authenticated(heartbeatIntervalSecs: value.heartbeatIntervalSecs)
        case "openPairRoute":
            let value = try container.decode(OpenPairRouteWire.self, forKey: .frame)
            self = .openPairRoute(
                machineRoute: value.machineRoute,
                pairRoute: value.pairRoute,
                absoluteExpiryMs: value.absoluteExpiryMs
            )
        case "pairRouteOpened":
            let value = try container.decode(OpenPairRouteWire.self, forKey: .frame)
            self = .pairRouteOpened(
                machineRoute: value.machineRoute,
                pairRoute: value.pairRoute,
                absoluteExpiryMs: value.absoluteExpiryMs
            )
        case "pairData":
            let value = try container.decode(PairDataWire.self, forKey: .frame)
            self = .pairData(pairRoute: value.pairRoute, sealedBlob: value.sealedBlob)
        case "closePairRoute":
            let value = try container.decode(ClosePairRouteWire.self, forKey: .frame)
            self = .closePairRoute(machineRoute: value.machineRoute, pairRoute: value.pairRoute)
        case "pairRouteClosed":
            let value = try container.decode(PairRouteClosedWire.self, forKey: .frame)
            self = .pairRouteClosed(pairRoute: value.pairRoute, outcome: value.outcome)
        case "registerStream":
            let value = try container.decode(RegisterStreamWire.self, forKey: .frame)
            self = .registerStream(
                machineRoute: value.machineRoute,
                streamRoute: value.streamRoute,
                generation: value.generation
            )
        case "publish":
            let value = try container.decode(PublishWire.self, forKey: .frame)
            self = .publish(
                streamRoute: value.streamRoute,
                generation: value.generation,
                streamSeq: value.streamSeq,
                sealedBlob: value.sealedBlob
            )
        case "subscribe":
            let value = try container.decode(SubscribeWire.self, forKey: .frame)
            self = .subscribe(
                streamRoute: value.streamRoute,
                generation: value.generation,
                cursor: value.cursor
            )
        case "unsubscribe":
            let value = try container.decode(StreamIdentityWire.self, forKey: .frame)
            self = .unsubscribe(streamRoute: value.streamRoute, generation: value.generation)
        case "ack":
            let value = try container.decode(AckWire.self, forKey: .frame)
            self = .ack(
                streamRoute: value.streamRoute,
                generation: value.generation,
                upToSeq: value.upToSeq
            )
        case "gap":
            let value = try container.decode(GapWire.self, forKey: .frame)
            self = .gap(
                streamRoute: value.streamRoute,
                generation: value.generation,
                needStreamSeq: value.needStreamSeq,
                oldestStreamSeq: value.oldestStreamSeq
            )
        case "replayComplete":
            let value = try container.decode(ReplayCompleteWire.self, forKey: .frame)
            self = .replayComplete(
                streamRoute: value.streamRoute,
                generation: value.generation,
                currentCursor: value.currentCursor
            )
        case "send":
            let value = try container.decode(DirectedDataWire.self, forKey: .frame)
            self = .send(
                deviceRoute: value.deviceRoute,
                requestRoute: value.requestRoute,
                sealedBlob: value.sealedBlob
            )
        case "reply":
            let value = try container.decode(DirectedDataWire.self, forKey: .frame)
            self = .reply(
                deviceRoute: value.deviceRoute,
                requestRoute: value.requestRoute,
                sealedBlob: value.sealedBlob
            )
        case "installGrant":
            self = .installGrant(
                grant: try container.decode(InstallGrantWire.self, forKey: .frame).grant
            )
        case "grantCommitted":
            let value = try container.decode(GrantCommittedWire.self, forKey: .frame)
            self = .grantCommitted(
                deviceRoute: value.deviceRoute,
                grantSerial: value.grantSerial,
                grantHash: value.grantHash
            )
        case "revokeDevice":
            self = .revokeDevice(
                revocation: try container.decode(RevokeDeviceWire.self, forKey: .frame).revocation
            )
        case "revocationCommitted":
            let value = try container.decode(RevocationCommittedWire.self, forKey: .frame)
            self = .revocationCommitted(
                deviceRoute: value.deviceRoute,
                grantSerial: value.grantSerial,
                signedRevocation: value.signedRevocation
            )
        case "retireMachine":
            let value = try container.decode(RetireMachineWire.self, forKey: .frame)
            self = .retireMachine(
                machineRoute: value.machineRoute,
                trustEpoch: value.trustEpoch,
                signature: value.signature
            )
        case "ping":
            self = .ping(nonce: try container.decode(NonceWire.self, forKey: .frame).nonce)
        case "pong":
            self = .pong(nonce: try container.decode(NonceWire.self, forKey: .frame).nonce)
        case "routeAccepted":
            self = .routeAccepted(
                accepted: try container.decode(RouteAcceptedWire.self, forKey: .frame).accepted
            )
        case "error": self = .error(try container.decode(RelayV2Failure.self, forKey: .frame))
        case "serverRestarting":
            self = .serverRestarting(
                drainDeadlineMs: try container.decode(
                    ServerRestartingWire.self,
                    forKey: .frame
                ).drainDeadlineMs
            )
        case let value:
            throw DecodingError.dataCorruptedError(
                forKey: .frameKind,
                in: container,
                debugDescription: "unsupported Relay v2 frame kind \(value)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .hello(let value):
            try container.encode("hello", forKey: .frameKind)
            try container.encode(value, forKey: .frame)
        case .challenge(let relayServerId, let connectionInstance, let challengeNonce):
            try container.encode("challenge", forKey: .frameKind)
            try container.encode(
                ChallengeWire(
                    relayServerId: relayServerId,
                    connectionInstance: connectionInstance,
                    challengeNonce: challengeNonce
                ),
                forKey: .frame
            )
        case .authenticate(let proof, let signature):
            try container.encode("authenticate", forKey: .frameKind)
            try container.encode(AuthenticateWire(proof: proof, signature: signature), forKey: .frame)
        case .authenticated(let heartbeatIntervalSecs):
            try container.encode("authenticated", forKey: .frameKind)
            try container.encode(
                AuthenticatedWire(heartbeatIntervalSecs: heartbeatIntervalSecs),
                forKey: .frame
            )
        case .openPairRoute(let machineRoute, let pairRoute, let absoluteExpiryMs),
             .pairRouteOpened(let machineRoute, let pairRoute, let absoluteExpiryMs):
            let name = kind == 4 ? "openPairRoute" : "pairRouteOpened"
            try container.encode(name, forKey: .frameKind)
            try container.encode(
                OpenPairRouteWire(
                    machineRoute: machineRoute,
                    pairRoute: pairRoute,
                    absoluteExpiryMs: absoluteExpiryMs
                ),
                forKey: .frame
            )
        case .pairData(let pairRoute, let sealedBlob):
            try container.encode("pairData", forKey: .frameKind)
            try container.encode(PairDataWire(pairRoute: pairRoute, sealedBlob: sealedBlob), forKey: .frame)
        case .closePairRoute(let machineRoute, let pairRoute):
            try container.encode("closePairRoute", forKey: .frameKind)
            try container.encode(
                ClosePairRouteWire(machineRoute: machineRoute, pairRoute: pairRoute),
                forKey: .frame
            )
        case .pairRouteClosed(let pairRoute, let outcome):
            try container.encode("pairRouteClosed", forKey: .frameKind)
            try container.encode(PairRouteClosedWire(pairRoute: pairRoute, outcome: outcome), forKey: .frame)
        case .registerStream(let machineRoute, let streamRoute, let generation):
            try container.encode("registerStream", forKey: .frameKind)
            try container.encode(
                RegisterStreamWire(
                    machineRoute: machineRoute,
                    streamRoute: streamRoute,
                    generation: generation
                ),
                forKey: .frame
            )
        case .publish(let streamRoute, let generation, let streamSeq, let sealedBlob):
            try container.encode("publish", forKey: .frameKind)
            try container.encode(
                PublishWire(
                    streamRoute: streamRoute,
                    generation: generation,
                    streamSeq: streamSeq,
                    sealedBlob: sealedBlob
                ),
                forKey: .frame
            )
        case .subscribe(let streamRoute, let generation, let cursor):
            try container.encode("subscribe", forKey: .frameKind)
            try container.encode(
                SubscribeWire(streamRoute: streamRoute, generation: generation, cursor: cursor),
                forKey: .frame
            )
        case .unsubscribe(let streamRoute, let generation):
            try container.encode("unsubscribe", forKey: .frameKind)
            try container.encode(
                StreamIdentityWire(streamRoute: streamRoute, generation: generation),
                forKey: .frame
            )
        case .ack(let streamRoute, let generation, let upToSeq):
            try container.encode("ack", forKey: .frameKind)
            try container.encode(
                AckWire(streamRoute: streamRoute, generation: generation, upToSeq: upToSeq),
                forKey: .frame
            )
        case .gap(let streamRoute, let generation, let needStreamSeq, let oldestStreamSeq):
            try container.encode("gap", forKey: .frameKind)
            try container.encode(
                GapWire(
                    streamRoute: streamRoute,
                    generation: generation,
                    needStreamSeq: needStreamSeq,
                    oldestStreamSeq: oldestStreamSeq
                ),
                forKey: .frame
            )
        case .replayComplete(let streamRoute, let generation, let currentCursor):
            try container.encode("replayComplete", forKey: .frameKind)
            try container.encode(
                ReplayCompleteWire(
                    streamRoute: streamRoute,
                    generation: generation,
                    currentCursor: currentCursor
                ),
                forKey: .frame
            )
        case .send(let deviceRoute, let requestRoute, let sealedBlob),
             .reply(let deviceRoute, let requestRoute, let sealedBlob):
            try container.encode(kind == 16 ? "send" : "reply", forKey: .frameKind)
            try container.encode(
                DirectedDataWire(
                    deviceRoute: deviceRoute,
                    requestRoute: requestRoute,
                    sealedBlob: sealedBlob
                ),
                forKey: .frame
            )
        case .installGrant(let grant):
            try container.encode("installGrant", forKey: .frameKind)
            try container.encode(InstallGrantWire(grant: grant), forKey: .frame)
        case .grantCommitted(let deviceRoute, let grantSerial, let grantHash):
            try container.encode("grantCommitted", forKey: .frameKind)
            try container.encode(
                GrantCommittedWire(
                    deviceRoute: deviceRoute,
                    grantSerial: grantSerial,
                    grantHash: grantHash
                ),
                forKey: .frame
            )
        case .revokeDevice(let revocation):
            try container.encode("revokeDevice", forKey: .frameKind)
            try container.encode(RevokeDeviceWire(revocation: revocation), forKey: .frame)
        case .revocationCommitted(let deviceRoute, let grantSerial, let signedRevocation):
            try container.encode("revocationCommitted", forKey: .frameKind)
            try container.encode(
                RevocationCommittedWire(
                    deviceRoute: deviceRoute,
                    grantSerial: grantSerial,
                    signedRevocation: signedRevocation
                ),
                forKey: .frame
            )
        case .retireMachine(let machineRoute, let trustEpoch, let signature):
            try container.encode("retireMachine", forKey: .frameKind)
            try container.encode(
                RetireMachineWire(
                    machineRoute: machineRoute,
                    trustEpoch: trustEpoch,
                    signature: signature
                ),
                forKey: .frame
            )
        case .ping(let nonce), .pong(let nonce):
            try container.encode(kind == 23 ? "ping" : "pong", forKey: .frameKind)
            try container.encode(NonceWire(nonce: nonce), forKey: .frame)
        case .routeAccepted(let accepted):
            try container.encode("routeAccepted", forKey: .frameKind)
            try container.encode(RouteAcceptedWire(accepted: accepted), forKey: .frame)
        case .error(let failure):
            try container.encode("error", forKey: .frameKind)
            try container.encode(failure, forKey: .frame)
        case .serverRestarting(let drainDeadlineMs):
            try container.encode("serverRestarting", forKey: .frameKind)
            try container.encode(
                ServerRestartingWire(drainDeadlineMs: drainDeadlineMs),
                forKey: .frame
            )
        }
    }
}

/// Public outbound control surface. Data-bearing pair/publish/request frames are deliberately
/// absent; those can only be built through `RelayV2OutboundFrame` typed factories below.
public enum RelayV2OutboundControlFrame: Sendable {
    case hello(RelayV2Hello)
    case challenge(relayServerId: Data, connectionInstance: Data, challengeNonce: Data)
    case authenticate(proof: RelayV2AuthProof, signature: Data)
    case authenticated(heartbeatIntervalSecs: UInt16)
    case openPairRoute(machineRoute: Data, pairRoute: Data, absoluteExpiryMs: UInt64)
    case pairRouteOpened(machineRoute: Data, pairRoute: Data, absoluteExpiryMs: UInt64)
    case closePairRoute(machineRoute: Data, pairRoute: Data)
    case pairRouteClosed(pairRoute: Data, outcome: RelayV2PairRouteCloseOutcome)
    case registerStream(machineRoute: Data, streamRoute: Data, generation: Data)
    case subscribe(streamRoute: Data, generation: Data, cursor: StreamCursor)
    case unsubscribe(streamRoute: Data, generation: Data)
    case ack(streamRoute: Data, generation: Data, upToSeq: UInt64)
    case gap(streamRoute: Data, generation: Data, needStreamSeq: UInt64, oldestStreamSeq: UInt64)
    case replayComplete(streamRoute: Data, generation: Data, currentCursor: StreamCursor)
    case installGrant(grant: RelayV2Grant)
    case grantCommitted(deviceRoute: Data, grantSerial: UInt64, grantHash: Data)
    case revokeDevice(revocation: RelayV2DeviceRevocation)
    case revocationCommitted(
        deviceRoute: Data,
        grantSerial: UInt64,
        signedRevocation: RelayV2DeviceRevocation
    )
    case retireMachine(machineRoute: Data, trustEpoch: UInt64, signature: Data)
    case ping(nonce: UInt64)
    case pong(nonce: UInt64)
    case routeAccepted(accepted: RelayV2AcceptedRef)
    case error(RelayV2Failure)
    case serverRestarting(drainDeadlineMs: UInt64)

    fileprivate var body: RelayV2FrameBody {
        switch self {
        case .hello(let value): .hello(value)
        case .challenge(let relayServerId, let connectionInstance, let challengeNonce):
            .challenge(
                relayServerId: relayServerId,
                connectionInstance: connectionInstance,
                challengeNonce: challengeNonce
            )
        case .authenticate(let proof, let signature):
            .authenticate(proof: proof, signature: signature)
        case .authenticated(let interval): .authenticated(heartbeatIntervalSecs: interval)
        case .openPairRoute(let machineRoute, let pairRoute, let expiry):
            .openPairRoute(
                machineRoute: machineRoute,
                pairRoute: pairRoute,
                absoluteExpiryMs: expiry
            )
        case .pairRouteOpened(let machineRoute, let pairRoute, let expiry):
            .pairRouteOpened(
                machineRoute: machineRoute,
                pairRoute: pairRoute,
                absoluteExpiryMs: expiry
            )
        case .closePairRoute(let machineRoute, let pairRoute):
            .closePairRoute(machineRoute: machineRoute, pairRoute: pairRoute)
        case .pairRouteClosed(let pairRoute, let outcome):
            .pairRouteClosed(pairRoute: pairRoute, outcome: outcome)
        case .registerStream(let machineRoute, let streamRoute, let generation):
            .registerStream(
                machineRoute: machineRoute,
                streamRoute: streamRoute,
                generation: generation
            )
        case .subscribe(let streamRoute, let generation, let cursor):
            .subscribe(streamRoute: streamRoute, generation: generation, cursor: cursor)
        case .unsubscribe(let streamRoute, let generation):
            .unsubscribe(streamRoute: streamRoute, generation: generation)
        case .ack(let streamRoute, let generation, let upToSeq):
            .ack(streamRoute: streamRoute, generation: generation, upToSeq: upToSeq)
        case .gap(let streamRoute, let generation, let need, let oldest):
            .gap(
                streamRoute: streamRoute,
                generation: generation,
                needStreamSeq: need,
                oldestStreamSeq: oldest
            )
        case .replayComplete(let streamRoute, let generation, let cursor):
            .replayComplete(
                streamRoute: streamRoute,
                generation: generation,
                currentCursor: cursor
            )
        case .installGrant(let grant): .installGrant(grant: grant)
        case .grantCommitted(let deviceRoute, let serial, let hash):
            .grantCommitted(deviceRoute: deviceRoute, grantSerial: serial, grantHash: hash)
        case .revokeDevice(let revocation): .revokeDevice(revocation: revocation)
        case .revocationCommitted(let deviceRoute, let serial, let revocation):
            .revocationCommitted(
                deviceRoute: deviceRoute,
                grantSerial: serial,
                signedRevocation: revocation
            )
        case .retireMachine(let machineRoute, let epoch, let signature):
            .retireMachine(machineRoute: machineRoute, trustEpoch: epoch, signature: signature)
        case .ping(let nonce): .ping(nonce: nonce)
        case .pong(let nonce): .pong(nonce: nonce)
        case .routeAccepted(let accepted): .routeAccepted(accepted: accepted)
        case .error(let failure): .error(failure)
        case .serverRestarting(let deadline): .serverRestarting(drainDeadlineMs: deadline)
        }
    }
}

/// The only public binary-encode input. Its initializer is private so callers cannot inject
/// arbitrary `sealedBlob: Data` into the production outbound path.
public struct RelayV2OutboundFrame: Sendable {
    fileprivate let frame: RelayV2Frame

    private init(body: RelayV2FrameBody) {
        frame = RelayV2Frame(version: relayProtocolVersionV2, body: body)
    }

    public static func control(_ value: RelayV2OutboundControlFrame) -> Self {
        Self(body: value.body)
    }

    public static func hello(protocolVersion: UInt16 = relayProtocolVersionV2) -> Self {
        control(.hello(RelayV2Hello(protocolVersion: protocolVersion)))
    }

    public static func pairData(
        pairRoute: Data,
        payload: RelayEndpointPayloadV1
    ) throws -> Self {
        Self(
            body: .pairData(
                pairRoute: pairRoute,
                sealedBlob: try RelayV2JSONCodec.encodeEndpoint(payload)
            )
        )
    }

    public static func publish(
        streamRoute: Data,
        generation: Data,
        streamSeq: UInt64,
        sealedBlob: SignedSealedBlobV1
    ) throws -> Self {
        Self(
            body: .publish(
                streamRoute: streamRoute,
                generation: generation,
                streamSeq: streamSeq,
                sealedBlob: try RelayV2SignedSealedBlobCodec.encode(sealedBlob)
            )
        )
    }

    public static func send(
        deviceRoute: Data,
        requestRoute: Data,
        sealedBlob: SignedSealedBlobV1
    ) throws -> Self {
        Self(
            body: .send(
                deviceRoute: deviceRoute,
                requestRoute: requestRoute,
                sealedBlob: try RelayV2SignedSealedBlobCodec.encode(sealedBlob)
            )
        )
    }

    public static func reply(
        deviceRoute: Data,
        requestRoute: Data,
        sealedBlob: SignedSealedBlobV1
    ) throws -> Self {
        Self(
            body: .reply(
                deviceRoute: deviceRoute,
                requestRoute: requestRoute,
                sealedBlob: try RelayV2SignedSealedBlobCodec.encode(sealedBlob)
            )
        )
    }
}

private enum RelayV2SignedSealedBlobCodec {
    private static let domain = Data("AgentDeck/SealedBlobV1\0".utf8)

    static func encode(_ value: SignedSealedBlobV1) throws -> Data {
        guard value.inner.formatVersion == 1 else {
            throw RelayWireCodecError.unsupportedVersion(value.inner.formatVersion)
        }
        guard value.inner.nonce.count == 12 else {
            throw RelayWireCodecError.invalidLength(
                field: "nonce",
                expected: 12,
                actual: value.inner.nonce.count
            )
        }
        guard value.signature.count == 64 else {
            throw RelayWireCodecError.invalidLength(
                field: "signature",
                expected: 64,
                actual: value.signature.count
            )
        }

        let fixedCapacity = domain.count + 2 + 1 + 1 + 8 + 8 + 8 + 4 + 12 + 4 + 64
        let (capacity, capacityOverflow) = fixedCapacity.addingReportingOverflow(
            value.inner.ciphertext.count
        )
        guard !capacityOverflow else {
            throw RelayWireCodecError.lengthOutOfBounds
        }
        var output = Data()
        output.reserveCapacity(capacity)
        output.append(domain)
        appendBigEndian(value.inner.formatVersion, to: &output)
        output.append(value.inner.payloadKind.canonicalTag)
        output.append(value.inner.keyID.purpose.canonicalTag)
        appendBigEndian(value.inner.keyID.epoch, to: &output)
        appendBigEndian(value.inner.keyEpoch, to: &output)
        appendBigEndian(value.inner.keyDirectoryRevision, to: &output)
        try appendLengthPrefixed(value.inner.nonce, field: "nonce", to: &output)
        try appendLengthPrefixed(value.inner.ciphertext, field: "ciphertext", to: &output)
        output.append(value.signature)
        return output
    }

    private static func appendLengthPrefixed(
        _ value: Data,
        field: String,
        to output: inout Data
    ) throws {
        guard let length = UInt32(exactly: value.count) else {
            throw RelayWireCodecError.lengthOutOfBounds
        }
        appendBigEndian(length, to: &output)
        output.append(value)
    }

    private static func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var value = value.bigEndian
        Swift.withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }
    }
}

extension StreamCursor: Codable {
    public init(from decoder: Decoder) throws {
        if let single = try? decoder.singleValueContainer(),
           let value = try? single.decode(String.self),
           value == "beforeFirst" {
            self = .beforeFirst
            return
        }
        let container = try decoder.container(keyedBy: RelayJSONCodingKey.self)
        guard container.allKeys.map(\.stringValue) == ["at"] else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "invalid stream cursor")
            )
        }
        self = .at(try container.decode(UInt64.self, forKey: relayKey("at")))
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .beforeFirst:
            var container = encoder.singleValueContainer()
            try container.encode("beforeFirst")
        case .at(let value):
            var container = encoder.container(keyedBy: RelayJSONCodingKey.self)
            try container.encode(value, forKey: relayKey("at"))
        }
    }
}

extension KeyIDV1: Codable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case purpose, epoch
    }

    public init(from decoder: Decoder) throws {
        try rejectRelayUnknownKeys(decoder, allowed: CodingKeys.all)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        purpose = try container.decode(KeyPurpose.self, forKey: .purpose)
        epoch = try container.decode(UInt64.self, forKey: .epoch)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(purpose, forKey: .purpose)
        try container.encode(epoch, forKey: .epoch)
    }
}

private struct ChallengeWire: Codable {
    let relayServerId: Data
    let connectionInstance: Data
    let challengeNonce: Data
}
private struct AuthenticateWire: Codable { let proof: RelayV2AuthProof; let signature: Data }
private struct AuthenticatedWire: Codable { let heartbeatIntervalSecs: UInt16 }
private struct OpenPairRouteWire: Codable {
    let machineRoute: Data
    let pairRoute: Data
    let absoluteExpiryMs: UInt64
}
private struct PairDataWire: Codable { let pairRoute: Data; let sealedBlob: Data }
private struct ClosePairRouteWire: Codable { let machineRoute: Data; let pairRoute: Data }
private struct PairRouteClosedWire: Codable {
    let pairRoute: Data
    let outcome: RelayV2PairRouteCloseOutcome
}
private struct RegisterStreamWire: Codable {
    let machineRoute: Data
    let streamRoute: Data
    let generation: Data
}
private struct PublishWire: Codable {
    let streamRoute: Data
    let generation: Data
    let streamSeq: UInt64
    let sealedBlob: Data
}
private struct SubscribeWire: Codable {
    let streamRoute: Data
    let generation: Data
    let cursor: StreamCursor
}
private struct StreamIdentityWire: Codable { let streamRoute: Data; let generation: Data }
private struct AckWire: Codable { let streamRoute: Data; let generation: Data; let upToSeq: UInt64 }
private struct GapWire: Codable {
    let streamRoute: Data
    let generation: Data
    let needStreamSeq: UInt64
    let oldestStreamSeq: UInt64
}
private struct ReplayCompleteWire: Codable {
    let streamRoute: Data
    let generation: Data
    let currentCursor: StreamCursor
}
private struct DirectedDataWire: Codable {
    let deviceRoute: Data
    let requestRoute: Data
    let sealedBlob: Data
}
private struct InstallGrantWire: Codable { let grant: RelayV2Grant }
private struct GrantCommittedWire: Codable {
    let deviceRoute: Data
    let grantSerial: UInt64
    let grantHash: Data
}
private struct RevokeDeviceWire: Codable { let revocation: RelayV2DeviceRevocation }
private struct RevocationCommittedWire: Codable {
    let deviceRoute: Data
    let grantSerial: UInt64
    let signedRevocation: RelayV2DeviceRevocation
}
private struct RetireMachineWire: Codable {
    let machineRoute: Data
    let trustEpoch: UInt64
    let signature: Data
}
private struct NonceWire: Codable { let nonce: UInt64 }
private struct RouteAcceptedWire: Codable { let accepted: RelayV2AcceptedRef }
private struct ServerRestartingWire: Codable { let drainDeadlineMs: UInt64 }
private struct MachineLinkProofWire: Codable {
    let machine_route: Data
    let link_cert: RelayV2SignedCertificate
}
private struct DeviceProofWire: Codable { let relay_grant: RelayV2Grant }
private struct RequestAcceptedWire: Codable { let request_route: Data }
private struct StreamAcceptedWire: Codable { let stream_route: Data; let stream_seq: UInt64 }
private struct PairAcceptedWire: Codable { let pair_route: Data }

public enum RelayV2JSONCodec {
    public static func decodeFrame(_ data: Data) throws -> RelayV2Frame {
        guard data.count <= RelayWireCodecV2.maxFrameBytes else {
            throw RelayWireCodecError.oversize
        }
        let root = try jsonObject(data)
        try exactKeys(root, allowed: ["version", "body"], path: "frame")
        guard let body = root["body"] as? [String: Any] else {
            throw RelayWireCodecError.unknownField("frame.body")
        }
        try exactKeys(body, allowed: ["frameKind", "frame"], path: "frame.body")
        guard let frameKind = body["frameKind"] as? String,
              let payload = body["frame"] as? [String: Any] else {
            throw RelayWireCodecError.unknownKind(UInt16.max)
        }
        switch frameKind {
        case "hello":
            try exactKeys(payload, allowed: ["protocolVersion"], path: "frame.body.frame")
        case "challenge":
            try exactKeys(
                payload,
                allowed: ["relayServerId", "connectionInstance", "challengeNonce"],
                path: "frame.body.frame"
            )
        case "ping", "pong":
            try exactKeys(payload, allowed: ["nonce"], path: "frame.body.frame")
        case "routeAccepted":
            try exactKeys(payload, allowed: ["accepted"], path: "frame.body.frame")
            guard let accepted = payload["accepted"] as? [String: Any],
                  accepted.count == 1,
                  let variant = accepted.keys.first,
                  let acceptedPayload = accepted[variant] as? [String: Any]
            else {
                throw RelayWireCodecError.unknownField("frame.body.frame.accepted")
            }
            switch variant {
            case "request":
                try exactKeys(
                    acceptedPayload,
                    allowed: ["request_route"],
                    path: "frame.body.frame.accepted.request"
                )
            case "streamFrame":
                try exactKeys(
                    acceptedPayload,
                    allowed: ["stream_route", "stream_seq"],
                    path: "frame.body.frame.accepted.streamFrame"
                )
            case "pairFrame":
                try exactKeys(
                    acceptedPayload,
                    allowed: ["pair_route"],
                    path: "frame.body.frame.accepted.pairFrame"
                )
            default:
                throw RelayWireCodecError.unknownField("frame.body.frame.accepted.\(variant)")
            }
        case "error":
            try exactKeys(
                payload,
                allowed: ["code", "message", "inReplyTo"],
                path: "frame.body.frame"
            )
        case "serverRestarting":
            try exactKeys(
                payload,
                allowed: ["drainDeadlineMs"],
                path: "frame.body.frame"
            )
        case "send", "reply":
            try exactKeys(
                payload,
                allowed: ["deviceRoute", "requestRoute", "sealedBlob"],
                path: "frame.body.frame"
            )
        case "installGrant":
            try exactKeys(payload, allowed: ["grant"], path: "frame.body.frame")
            try validateGrant(payload["grant"], path: "frame.body.frame.grant")
        case "grantCommitted":
            try exactKeys(
                payload,
                allowed: ["deviceRoute", "grantSerial", "grantHash"],
                path: "frame.body.frame"
            )
        case "revokeDevice":
            try exactKeys(payload, allowed: ["revocation"], path: "frame.body.frame")
            try validateRevocation(payload["revocation"], path: "frame.body.frame.revocation")
        case "revocationCommitted":
            try exactKeys(
                payload,
                allowed: ["deviceRoute", "grantSerial", "signedRevocation"],
                path: "frame.body.frame"
            )
            try validateRevocation(
                payload["signedRevocation"],
                path: "frame.body.frame.signedRevocation"
            )
        case "retireMachine":
            try exactKeys(
                payload,
                allowed: ["machineRoute", "trustEpoch", "signature"],
                path: "frame.body.frame"
            )
        case "registerStream":
            try exactKeys(
                payload,
                allowed: ["machineRoute", "streamRoute", "generation"],
                path: "frame.body.frame"
            )
        case "publish":
            try exactKeys(
                payload,
                allowed: ["streamRoute", "generation", "streamSeq", "sealedBlob"],
                path: "frame.body.frame"
            )
        case "subscribe":
            try exactKeys(
                payload,
                allowed: ["streamRoute", "generation", "cursor"],
                path: "frame.body.frame"
            )
        case "unsubscribe":
            try exactKeys(
                payload,
                allowed: ["streamRoute", "generation"],
                path: "frame.body.frame"
            )
        case "ack":
            try exactKeys(
                payload,
                allowed: ["streamRoute", "generation", "upToSeq"],
                path: "frame.body.frame"
            )
        case "gap":
            try exactKeys(
                payload,
                allowed: ["streamRoute", "generation", "needStreamSeq", "oldestStreamSeq"],
                path: "frame.body.frame"
            )
        case "replayComplete":
            try exactKeys(
                payload,
                allowed: ["streamRoute", "generation", "currentCursor"],
                path: "frame.body.frame"
            )
        case "authenticate":
            try exactKeys(payload, allowed: ["proof", "signature"], path: "frame.body.frame")
            guard let proof = payload["proof"] as? [String: Any],
                  proof.count == 1,
                  let variant = proof.keys.first,
                  let proofPayload = proof[variant] as? [String: Any]
            else {
                throw RelayWireCodecError.unknownField("frame.body.frame.proof")
            }
            switch variant {
            case "machineLink":
                try exactKeys(
                    proofPayload,
                    allowed: ["machine_route", "link_cert"],
                    path: "frame.body.frame.proof.machineLink"
                )
                try validateCertificate(
                    proofPayload["link_cert"],
                    path: "frame.body.frame.proof.machineLink.link_cert"
                )
            case "device":
                try exactKeys(
                    proofPayload,
                    allowed: ["relay_grant"],
                    path: "frame.body.frame.proof.device"
                )
                try validateGrant(
                    proofPayload["relay_grant"],
                    path: "frame.body.frame.proof.device.relay_grant"
                )
            default: throw RelayWireCodecError.unknownField("frame.body.frame.proof.\(variant)")
            }
        case "authenticated":
            try exactKeys(
                payload,
                allowed: ["heartbeatIntervalSecs"],
                path: "frame.body.frame"
            )
        case "openPairRoute", "pairRouteOpened":
            try exactKeys(
                payload,
                allowed: ["machineRoute", "pairRoute", "absoluteExpiryMs"],
                path: "frame.body.frame"
            )
        case "pairData":
            try exactKeys(
                payload,
                allowed: ["pairRoute", "sealedBlob"],
                path: "frame.body.frame"
            )
        case "closePairRoute":
            try exactKeys(
                payload,
                allowed: ["machineRoute", "pairRoute"],
                path: "frame.body.frame"
            )
        case "pairRouteClosed":
            try exactKeys(
                payload,
                allowed: ["pairRoute", "outcome"],
                path: "frame.body.frame"
            )
        default:
            throw RelayWireCodecError.unknownKind(UInt16.max)
        }
        let frame = try JSONDecoder().decode(RelayV2Frame.self, from: data)
        guard frame.version == relayProtocolVersionV2 else {
            throw RelayWireCodecError.unsupportedVersion(frame.version)
        }
        _ = try RelayWireCodecV2.encodeFixture(frame)
        return frame
    }

    public static func decodeEndpoint(
        _ wireType: RelayEndpointWireType,
        from data: Data
    ) throws -> RelayEndpointPayloadV1 {
        guard data.count <= RelayWireCodecV2.maxFrameBytes else {
            throw RelayWireCodecError.oversize
        }
        let object = try jsonObject(data)
        try validateEndpointObject(object, wireType: wireType)
        let decoder = JSONDecoder()
        let payload: RelayEndpointPayloadV1
        switch wireType {
        case .pairInvite:
            payload = .pairInvite(try decoder.decode(RelayPairInviteV1.self, from: data))
        case .pairRequest:
            payload = .pairRequest(try decoder.decode(RelayPairRequestV1.self, from: data))
        case .pairResponse:
            payload = .pairResponse(try decoder.decode(RelayPairResponseV1.self, from: data))
        case .deviceAuthorization:
            payload = .deviceAuthorization(
                try decoder.decode(RelayDeviceAuthorizationV1.self, from: data)
            )
        case .keyDirectory:
            payload = .keyDirectory(try decoder.decode(RelayKeyDirectoryV1.self, from: data))
        case .keyUpdate:
            payload = .keyUpdate(try decoder.decode(RelayKeyUpdateV1.self, from: data))
        case .epochBarrier:
            payload = .epochBarrier(try decoder.decode(RelayEpochBarrierV1.self, from: data))
        case .sealedPayload:
            payload = .sealedPayload(try decoder.decode(RelaySealedPayloadV1.self, from: data))
        }
        try validateEndpointLengths(payload)
        return payload
    }

    public static func encodeEndpoint(_ payload: RelayEndpointPayloadV1) throws -> Data {
        try validateEndpointLengths(payload)
        let encoder = JSONEncoder()
        switch payload {
        case .pairInvite(let value): return try encoder.encode(value)
        case .pairRequest(let value): return try encoder.encode(value)
        case .pairResponse(let value): return try encoder.encode(value)
        case .deviceAuthorization(let value): return try encoder.encode(value)
        case .keyDirectory(let value): return try encoder.encode(value)
        case .keyUpdate(let value): return try encoder.encode(value)
        case .epochBarrier(let value): return try encoder.encode(value)
        case .sealedPayload(let value): return try encoder.encode(value)
        }
    }

    private static func validateEndpointObject(
        _ object: [String: Any],
        wireType: RelayEndpointWireType
    ) throws {
        let path = wireType.rawValue
        switch wireType {
        case .pairInvite:
            try exactKeys(
                object,
                allowed: [
                    "formatVersion", "relayProtocolVersion", "pairRoute", "inviteSecret",
                    "inviteHpkePubkey", "wssUrl", "relayServerId", "currentSpkiPin",
                    "nextSpkiPin", "expiresAtMs", "machineRootPubkey",
                    "machineRootFingerprint", "dataSignCert", "machineDisplayName",
                ],
                path: path
            )
            try validateCertificate(object["dataSignCert"], path: "\(path).dataSignCert")
        case .pairRequest:
            try exactKeys(
                object,
                allowed: [
                    "formatVersion", "inviteSecret", "deviceSignPubkey", "deviceHpkePubkey",
                    "sealedAuthorizationRequest", "proofSignature",
                ],
                path: path
            )
        case .pairResponse:
            try exactKeys(
                object,
                allowed: [
                    "requestHash", "relayGrant", "sealedDeviceAuthorization", "keyDirectory",
                    "signature",
                ],
                path: path
            )
            try validateGrant(object["relayGrant"], path: "\(path).relayGrant")
            try validateKeyDirectory(object["keyDirectory"], path: "\(path).keyDirectory")
        case .deviceAuthorization:
            try exactKeys(
                object,
                allowed: [
                    "grantSerial", "deviceHpkePubkey", "capabilities", "permissions",
                    "rootKeyId", "trustEpoch", "signature",
                ],
                path: path
            )
        case .keyDirectory:
            try validateKeyDirectory(object, path: path)
        case .keyUpdate:
            try exactKeys(
                object,
                allowed: [
                    "keyDirectoryRevision", "keyId", "deviceRoute", "enc", "wrappedKey",
                    "signature",
                ],
                path: path
            )
            try validateKeyID(object["keyId"], path: "\(path).keyId")
        case .epochBarrier:
            try exactKeys(
                object,
                allowed: [
                    "streamGeneration", "streamCursor", "eventSeq", "oldEpoch", "newEpoch",
                    "keyDirectoryRevision",
                ],
                path: path
            )
            if let cursor = object["streamCursor"] as? [String: Any] {
                try exactKeys(cursor, allowed: ["at"], path: "\(path).streamCursor")
            }
        case .sealedPayload:
            try exactKeys(
                object,
                allowed: ["formatVersion", "payloadKind"],
                path: path
            )
        }
    }

    private static func validateKeyDirectory(_ value: Any?, path: String) throws {
        guard let object = value as? [String: Any] else {
            throw RelayWireCodecError.unknownField(path)
        }
        try exactKeys(object, allowed: ["revision", "entries", "signature"], path: path)
        guard let entries = object["entries"] as? [[String: Any]] else {
            throw RelayWireCodecError.unknownField("\(path).entries")
        }
        for (index, entry) in entries.enumerated() {
            let entryPath = "\(path).entries[\(index)]"
            try exactKeys(
                entry,
                allowed: ["keyId", "deviceRoute", "enc", "wrappedKey"],
                path: entryPath
            )
            try validateKeyID(entry["keyId"], path: "\(entryPath).keyId")
        }
    }

    private static func validateKeyID(_ value: Any?, path: String) throws {
        guard let object = value as? [String: Any] else {
            throw RelayWireCodecError.unknownField(path)
        }
        try exactKeys(object, allowed: ["purpose", "epoch"], path: path)
    }

    private static func validateEndpointLengths(_ payload: RelayEndpointPayloadV1) throws {
        switch payload {
        case .pairInvite(let value):
            try requireVersion(value.formatVersion, expected: 1, field: "formatVersion")
            try requireVersion(
                value.relayProtocolVersion,
                expected: relayProtocolVersionV2,
                field: "relayProtocolVersion"
            )
            try require(value.pairRoute, count: 16, field: "pairRoute")
            try require(value.inviteSecret, count: 32, field: "inviteSecret")
            try require(value.inviteHpkePubkey, count: 32, field: "inviteHpkePubkey")
            try require(value.relayServerId, count: 16, field: "relayServerId")
            try require(value.currentSpkiPin, count: 32, field: "currentSpkiPin")
            try require(value.nextSpkiPin, count: 32, field: "nextSpkiPin")
            try require(value.machineRootPubkey, count: 32, field: "machineRootPubkey")
            try require(
                value.machineRootFingerprint,
                count: 32,
                field: "machineRootFingerprint"
            )
            try validateCertificateLengths(value.dataSignCert)
        case .pairRequest(let value):
            try requireVersion(value.formatVersion, expected: 1, field: "formatVersion")
            try require(value.inviteSecret, count: 32, field: "inviteSecret")
            try require(value.deviceSignPubkey, count: 32, field: "deviceSignPubkey")
            try require(value.deviceHpkePubkey, count: 32, field: "deviceHpkePubkey")
            try require(value.proofSignature, count: 64, field: "proofSignature")
        case .pairResponse(let value):
            try require(value.requestHash, count: 32, field: "requestHash")
            try validateGrantLengths(value.relayGrant)
            try validateDirectoryLengths(value.keyDirectory)
            try require(value.signature, count: 64, field: "signature")
        case .deviceAuthorization(let value):
            try require(value.deviceHpkePubkey, count: 32, field: "deviceHpkePubkey")
            try require(value.rootKeyId, count: 16, field: "rootKeyId")
            try require(value.signature, count: 64, field: "signature")
        case .keyDirectory(let value): try validateDirectoryLengths(value)
        case .keyUpdate(let value):
            try require(value.deviceRoute, count: 16, field: "deviceRoute")
            try require(value.signature, count: 64, field: "signature")
        case .epochBarrier(let value):
            try require(value.streamGeneration, count: 16, field: "streamGeneration")
        case .sealedPayload(let value):
            try requireVersion(value.formatVersion, expected: 1, field: "formatVersion")
        }
    }

    private static func validateCertificateLengths(_ value: RelayV2SignedCertificate) throws {
        try require(value.subjectPubkey, count: 32, field: "subjectPubkey")
        try require(value.rootKeyId, count: 16, field: "rootKeyId")
        try require(value.signature, count: 64, field: "signature")
    }

    private static func validateGrantLengths(_ value: RelayV2Grant) throws {
        try require(value.machineRoute, count: 16, field: "machineRoute")
        try require(value.deviceRoute, count: 16, field: "deviceRoute")
        try require(value.deviceSignPubkey, count: 32, field: "deviceSignPubkey")
        try require(value.rootKeyId, count: 16, field: "rootKeyId")
        try require(value.signature, count: 64, field: "signature")
    }

    private static func validateDirectoryLengths(_ value: RelayKeyDirectoryV1) throws {
        try require(value.signature, count: 64, field: "keyDirectory.signature")
        for entry in value.entries {
            try require(entry.deviceRoute, count: 16, field: "keyDirectory.deviceRoute")
        }
    }

    private static func require(_ value: Data, count: Int, field: String) throws {
        guard value.count == count else {
            throw RelayWireCodecError.invalidLength(
                field: field,
                expected: count,
                actual: value.count
            )
        }
    }

    private static func requireVersion(
        _ value: UInt16,
        expected: UInt16,
        field: String
    ) throws {
        guard value == expected else {
            throw RelayWireCodecError.invalidVersion(
                field: field,
                expected: expected,
                actual: value
            )
        }
    }

    private static func jsonObject(_ data: Data) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw RelayWireCodecError.unknownField("frame")
        }
        return object
    }

    private static func exactKeys(
        _ object: [String: Any],
        allowed: Set<String>,
        path: String
    ) throws {
        if let unknown = object.keys.first(where: { !allowed.contains($0) }) {
            throw RelayWireCodecError.unknownField("\(path).\(unknown)")
        }
    }

    private static func validateCertificate(_ value: Any?, path: String) throws {
        guard let object = value as? [String: Any] else {
            throw RelayWireCodecError.unknownField(path)
        }
        try exactKeys(
            object,
            allowed: [
                "subjectPubkey", "certRole", "generation", "rootKeyId", "trustEpoch",
                "notAfterMs", "signature",
            ],
            path: path
        )
    }

    private static func validateGrant(_ value: Any?, path: String) throws {
        guard let object = value as? [String: Any] else {
            throw RelayWireCodecError.unknownField(path)
        }
        try exactKeys(
            object,
            allowed: [
                "machineRoute", "deviceRoute", "deviceSignPubkey", "grantSerial",
                "rootKeyId", "trustEpoch", "signature",
            ],
            path: path
        )
    }

    private static func validateRevocation(_ value: Any?, path: String) throws {
        guard let object = value as? [String: Any] else {
            throw RelayWireCodecError.unknownField(path)
        }
        try exactKeys(
            object,
            allowed: [
                "machineRoute", "deviceRoute", "grantSerial", "rootKeyId", "trustEpoch",
                "signature",
            ],
            path: path
        )
    }
}

public enum RelayWireCodecV2 {
    public static let maxFrameBytes = 4 * 1024 * 1024
    private static let magic = Data("ADRV2".utf8)

    public static func encode(_ frame: RelayV2OutboundFrame) throws -> Data {
        try encodeFixture(frame.frame)
    }

    static func encodeFixture(_ frame: RelayV2Frame) throws -> Data {
        guard frame.version == relayProtocolVersionV2 else {
            throw RelayWireCodecError.unsupportedVersion(frame.version)
        }
        var writer = RelayBinaryWriter()
        writer.raw(magic)
        writer.u16(frame.version)
        writer.u16(frame.body.kind)
        switch frame.body {
        case .hello(let hello): writer.u16(hello.protocolVersion)
        case .challenge(let relayServerId, let connectionInstance, let challengeNonce):
            try writer.fixed(relayServerId, count: 16, field: "relayServerId")
            try writer.fixed(connectionInstance, count: 16, field: "connectionInstance")
            try writer.fixed(challengeNonce, count: 32, field: "challengeNonce")
        case .authenticate(let proof, let signature):
            switch proof {
            case .machineLink(let machineRoute, let linkCert):
                writer.u8(0)
                try writer.fixed(machineRoute, count: 16, field: "machineRoute")
                try writer.certificate(linkCert)
            case .device(let relayGrant):
                writer.u8(1)
                try writer.grant(relayGrant)
            }
            try writer.fixed(signature, count: 64, field: "signature")
        case .authenticated(let heartbeatIntervalSecs):
            writer.u16(heartbeatIntervalSecs)
        case .openPairRoute(let machineRoute, let pairRoute, let absoluteExpiryMs),
             .pairRouteOpened(let machineRoute, let pairRoute, let absoluteExpiryMs):
            try writer.fixed(machineRoute, count: 16, field: "machineRoute")
            try writer.fixed(pairRoute, count: 16, field: "pairRoute")
            writer.u64(absoluteExpiryMs)
        case .pairData(let pairRoute, let sealedBlob):
            try writer.fixed(pairRoute, count: 16, field: "pairRoute")
            try writer.bytes(sealedBlob, field: "sealedBlob")
        case .closePairRoute(let machineRoute, let pairRoute):
            try writer.fixed(machineRoute, count: 16, field: "machineRoute")
            try writer.fixed(pairRoute, count: 16, field: "pairRoute")
        case .pairRouteClosed(let pairRoute, let outcome):
            try writer.fixed(pairRoute, count: 16, field: "pairRoute")
            writer.u8(outcome == .closed ? 0 : 1)
        case .registerStream(let machineRoute, let streamRoute, let generation):
            try writer.fixed(machineRoute, count: 16, field: "machineRoute")
            try writer.fixed(streamRoute, count: 16, field: "streamRoute")
            try writer.fixed(generation, count: 16, field: "generation")
        case .publish(let streamRoute, let generation, let streamSeq, let sealedBlob):
            try writer.fixed(streamRoute, count: 16, field: "streamRoute")
            try writer.fixed(generation, count: 16, field: "generation")
            writer.u64(streamSeq)
            try writer.bytes(sealedBlob, field: "sealedBlob")
        case .subscribe(let streamRoute, let generation, let cursor):
            try writer.fixed(streamRoute, count: 16, field: "streamRoute")
            try writer.fixed(generation, count: 16, field: "generation")
            writer.cursor(cursor)
        case .unsubscribe(let streamRoute, let generation):
            try writer.fixed(streamRoute, count: 16, field: "streamRoute")
            try writer.fixed(generation, count: 16, field: "generation")
        case .ack(let streamRoute, let generation, let upToSeq):
            try writer.fixed(streamRoute, count: 16, field: "streamRoute")
            try writer.fixed(generation, count: 16, field: "generation")
            writer.u64(upToSeq)
        case .gap(let streamRoute, let generation, let needStreamSeq, let oldestStreamSeq):
            try writer.fixed(streamRoute, count: 16, field: "streamRoute")
            try writer.fixed(generation, count: 16, field: "generation")
            writer.u64(needStreamSeq)
            writer.u64(oldestStreamSeq)
        case .replayComplete(let streamRoute, let generation, let currentCursor):
            try writer.fixed(streamRoute, count: 16, field: "streamRoute")
            try writer.fixed(generation, count: 16, field: "generation")
            writer.cursor(currentCursor)
        case .send(let deviceRoute, let requestRoute, let sealedBlob),
             .reply(let deviceRoute, let requestRoute, let sealedBlob):
            try writer.fixed(deviceRoute, count: 16, field: "deviceRoute")
            try writer.fixed(requestRoute, count: 16, field: "requestRoute")
            try writer.bytes(sealedBlob, field: "sealedBlob")
        case .installGrant(let grant):
            try writer.grant(grant)
        case .grantCommitted(let deviceRoute, let grantSerial, let grantHash):
            try writer.fixed(deviceRoute, count: 16, field: "deviceRoute")
            writer.u64(grantSerial)
            try writer.fixed(grantHash, count: 32, field: "grantHash")
        case .revokeDevice(let revocation):
            try writer.revocation(revocation)
        case .revocationCommitted(let deviceRoute, let grantSerial, let signedRevocation):
            try writer.fixed(deviceRoute, count: 16, field: "deviceRoute")
            writer.u64(grantSerial)
            try writer.revocation(signedRevocation)
        case .retireMachine(let machineRoute, let trustEpoch, let signature):
            try writer.fixed(machineRoute, count: 16, field: "machineRoute")
            writer.u64(trustEpoch)
            try writer.fixed(signature, count: 64, field: "signature")
        case .ping(let nonce), .pong(let nonce):
            writer.u64(nonce)
        case .routeAccepted(let accepted):
            switch accepted {
            case .request(let requestRoute):
                writer.u8(0)
                try writer.fixed(requestRoute, count: 16, field: "requestRoute")
            case .streamFrame(let streamRoute, let streamSeq):
                writer.u8(1)
                try writer.fixed(streamRoute, count: 16, field: "streamRoute")
                writer.u64(streamSeq)
            case .pairFrame(let pairRoute):
                writer.u8(2)
                try writer.fixed(pairRoute, count: 16, field: "pairRoute")
            }
        case .error(let failure):
            try writer.string(failure.code)
            try writer.string(failure.message)
            try writer.optionalString(failure.inReplyTo)
        case .serverRestarting(let drainDeadlineMs):
            writer.u64(drainDeadlineMs)
        }
        let data = writer.finish()
        guard data.count <= maxFrameBytes else {
            throw RelayWireCodecError.oversize
        }
        return data
    }

    public static func decode(_ data: Data) throws -> RelayV2Frame {
        guard data.count <= maxFrameBytes else {
            throw RelayWireCodecError.oversize
        }
        var reader = RelayBinaryReader(data)
        guard try reader.raw(count: magic.count) == magic else {
            throw RelayWireCodecError.badMagic
        }
        let version = try reader.u16()
        guard version == relayProtocolVersionV2 else {
            throw RelayWireCodecError.unsupportedVersion(version)
        }
        let kind = try reader.u16()
        let body: RelayV2FrameBody
        switch kind {
        case 0: body = .hello(RelayV2Hello(protocolVersion: try reader.u16()))
        case 1:
            body = .challenge(
                relayServerId: try reader.raw(count: 16),
                connectionInstance: try reader.raw(count: 16),
                challengeNonce: try reader.raw(count: 32)
            )
        case 2:
            let proof: RelayV2AuthProof
            switch try reader.u8() {
            case 0:
                proof = .machineLink(
                    machineRoute: try reader.raw(count: 16),
                    linkCert: try reader.certificate()
                )
            case 1: proof = .device(relayGrant: try reader.grant())
            case let tag: throw RelayWireCodecError.invalidEnumTag(tag)
            }
            body = .authenticate(proof: proof, signature: try reader.raw(count: 64))
        case 3: body = .authenticated(heartbeatIntervalSecs: try reader.u16())
        case 4:
            body = .openPairRoute(
                machineRoute: try reader.raw(count: 16),
                pairRoute: try reader.raw(count: 16),
                absoluteExpiryMs: try reader.u64()
            )
        case 5:
            body = .pairRouteOpened(
                machineRoute: try reader.raw(count: 16),
                pairRoute: try reader.raw(count: 16),
                absoluteExpiryMs: try reader.u64()
            )
        case 6:
            body = .pairData(
                pairRoute: try reader.raw(count: 16),
                sealedBlob: try reader.bytes()
            )
        case 7:
            body = .closePairRoute(
                machineRoute: try reader.raw(count: 16),
                pairRoute: try reader.raw(count: 16)
            )
        case 8:
            let pairRoute = try reader.raw(count: 16)
            let outcome: RelayV2PairRouteCloseOutcome
            switch try reader.u8() {
            case 0: outcome = .closed
            case 1: outcome = .alreadyAbsent
            case let tag: throw RelayWireCodecError.invalidEnumTag(tag)
            }
            body = .pairRouteClosed(pairRoute: pairRoute, outcome: outcome)
        case 9:
            body = .registerStream(
                machineRoute: try reader.raw(count: 16),
                streamRoute: try reader.raw(count: 16),
                generation: try reader.raw(count: 16)
            )
        case 10:
            body = .publish(
                streamRoute: try reader.raw(count: 16),
                generation: try reader.raw(count: 16),
                streamSeq: try reader.u64(),
                sealedBlob: try reader.bytes()
            )
        case 11:
            body = .subscribe(
                streamRoute: try reader.raw(count: 16),
                generation: try reader.raw(count: 16),
                cursor: try reader.cursor()
            )
        case 12:
            body = .unsubscribe(
                streamRoute: try reader.raw(count: 16),
                generation: try reader.raw(count: 16)
            )
        case 13:
            body = .ack(
                streamRoute: try reader.raw(count: 16),
                generation: try reader.raw(count: 16),
                upToSeq: try reader.u64()
            )
        case 14:
            body = .gap(
                streamRoute: try reader.raw(count: 16),
                generation: try reader.raw(count: 16),
                needStreamSeq: try reader.u64(),
                oldestStreamSeq: try reader.u64()
            )
        case 15:
            body = .replayComplete(
                streamRoute: try reader.raw(count: 16),
                generation: try reader.raw(count: 16),
                currentCursor: try reader.cursor()
            )
        case 16:
            body = .send(
                deviceRoute: try reader.raw(count: 16),
                requestRoute: try reader.raw(count: 16),
                sealedBlob: try reader.bytes()
            )
        case 17:
            body = .reply(
                deviceRoute: try reader.raw(count: 16),
                requestRoute: try reader.raw(count: 16),
                sealedBlob: try reader.bytes()
            )
        case 18: body = .installGrant(grant: try reader.grant())
        case 19:
            body = .grantCommitted(
                deviceRoute: try reader.raw(count: 16),
                grantSerial: try reader.u64(),
                grantHash: try reader.raw(count: 32)
            )
        case 20: body = .revokeDevice(revocation: try reader.revocation())
        case 21:
            body = .revocationCommitted(
                deviceRoute: try reader.raw(count: 16),
                grantSerial: try reader.u64(),
                signedRevocation: try reader.revocation()
            )
        case 22:
            body = .retireMachine(
                machineRoute: try reader.raw(count: 16),
                trustEpoch: try reader.u64(),
                signature: try reader.raw(count: 64)
            )
        case 23: body = .ping(nonce: try reader.u64())
        case 24: body = .pong(nonce: try reader.u64())
        case 25:
            let accepted: RelayV2AcceptedRef
            switch try reader.u8() {
            case 0: accepted = .request(requestRoute: try reader.raw(count: 16))
            case 1:
                accepted = .streamFrame(
                    streamRoute: try reader.raw(count: 16),
                    streamSeq: try reader.u64()
                )
            case 2: accepted = .pairFrame(pairRoute: try reader.raw(count: 16))
            case let tag: throw RelayWireCodecError.invalidEnumTag(tag)
            }
            body = .routeAccepted(accepted: accepted)
        case 26:
            body = .error(
                RelayV2Failure(
                    code: try reader.string(),
                    message: try reader.string(),
                    inReplyTo: try reader.optionalString()
                )
            )
        case 27: body = .serverRestarting(drainDeadlineMs: try reader.u64())
        default: throw RelayWireCodecError.unknownKind(kind)
        }
        guard reader.isAtEnd else {
            throw RelayWireCodecError.trailingBytes
        }
        return RelayV2Frame(version: version, body: body)
    }
}

private struct RelayBinaryWriter {
    private var storage = Data()
    private let maxBytes = RelayWireCodecV2.maxFrameBytes

    mutating func raw(_ value: Data) {
        storage.append(value)
    }

    mutating func u16(_ value: UInt16) {
        storage.append(UInt8(truncatingIfNeeded: value >> 8))
        storage.append(UInt8(truncatingIfNeeded: value))
    }

    mutating func u8(_ value: UInt8) {
        storage.append(value)
    }

    mutating func u32(_ value: UInt32) {
        storage.append(UInt8(truncatingIfNeeded: value >> 24))
        storage.append(UInt8(truncatingIfNeeded: value >> 16))
        storage.append(UInt8(truncatingIfNeeded: value >> 8))
        storage.append(UInt8(truncatingIfNeeded: value))
    }

    mutating func u64(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            storage.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }

    mutating func fixed(_ value: Data, count: Int, field: String) throws {
        guard value.count == count else {
            throw RelayWireCodecError.invalidLength(
                field: field,
                expected: count,
                actual: value.count
            )
        }
        raw(value)
    }

    mutating func bytes(_ value: Data, field: String) throws {
        guard let count = UInt32(exactly: value.count) else {
            throw RelayWireCodecError.lengthOutOfBounds
        }
        let (afterPrefix, prefixOverflow) = storage.count.addingReportingOverflow(4)
        let (afterValue, valueOverflow) = afterPrefix.addingReportingOverflow(value.count)
        guard !prefixOverflow, !valueOverflow, afterValue <= maxBytes else {
            throw RelayWireCodecError.oversize
        }
        u32(count)
        raw(value)
    }

    mutating func string(_ value: String) throws {
        try bytes(Data(value.utf8), field: "string")
    }

    mutating func optionalString(_ value: String?) throws {
        guard let value else {
            u8(0)
            return
        }
        u8(1)
        try string(value)
    }

    mutating func cursor(_ value: StreamCursor) {
        switch value {
        case .beforeFirst: u8(0)
        case .at(let cursor):
            u8(1)
            u64(cursor)
        }
    }

    mutating func certificate(_ value: RelayV2SignedCertificate) throws {
        try fixed(value.subjectPubkey, count: 32, field: "subjectPubkey")
        u8(value.certRole == .link ? 0 : 1)
        u64(value.generation)
        try fixed(value.rootKeyId, count: 16, field: "rootKeyId")
        u64(value.trustEpoch)
        if let notAfterMs = value.notAfterMs {
            u8(1)
            u64(notAfterMs)
        } else {
            u8(0)
        }
        try fixed(value.signature, count: 64, field: "signature")
    }

    mutating func grant(_ value: RelayV2Grant) throws {
        try fixed(value.machineRoute, count: 16, field: "machineRoute")
        try fixed(value.deviceRoute, count: 16, field: "deviceRoute")
        try fixed(value.deviceSignPubkey, count: 32, field: "deviceSignPubkey")
        u64(value.grantSerial)
        try fixed(value.rootKeyId, count: 16, field: "rootKeyId")
        u64(value.trustEpoch)
        try fixed(value.signature, count: 64, field: "signature")
    }

    mutating func revocation(_ value: RelayV2DeviceRevocation) throws {
        try fixed(value.machineRoute, count: 16, field: "machineRoute")
        try fixed(value.deviceRoute, count: 16, field: "deviceRoute")
        u64(value.grantSerial)
        try fixed(value.rootKeyId, count: 16, field: "rootKeyId")
        u64(value.trustEpoch)
        try fixed(value.signature, count: 64, field: "signature")
    }

    func finish() -> Data {
        storage
    }
}

private struct RelayBinaryReader {
    private let input: Data
    private var offset = 0

    init(_ input: Data) {
        self.input = input
    }

    var isAtEnd: Bool {
        offset == input.count
    }

    mutating func raw(count: Int) throws -> Data {
        guard count >= 0, offset <= input.count, count <= input.count - offset else {
            throw RelayWireCodecError.shortInput
        }
        let start = input.index(input.startIndex, offsetBy: offset)
        let end = input.index(start, offsetBy: count)
        offset += count
        return Data(input[start..<end])
    }

    mutating func u16() throws -> UInt16 {
        let bytes = try raw(count: 2)
        return bytes.reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
    }

    mutating func u8() throws -> UInt8 {
        try raw(count: 1)[0]
    }

    mutating func u32() throws -> UInt32 {
        try raw(count: 4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    mutating func u64() throws -> UInt64 {
        try raw(count: 8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    mutating func bytes() throws -> Data {
        guard let count = Int(exactly: try u32()) else {
            throw RelayWireCodecError.lengthOutOfBounds
        }
        guard count <= input.count - offset else {
            throw RelayWireCodecError.lengthOutOfBounds
        }
        return try raw(count: count)
    }

    mutating func string() throws -> String {
        guard let value = String(data: try bytes(), encoding: .utf8) else {
            throw RelayWireCodecError.invalidUTF8
        }
        return value
    }

    mutating func optionalString() throws -> String? {
        switch try u8() {
        case 0: nil
        case 1: try string()
        case let tag: throw RelayWireCodecError.invalidEnumTag(tag)
        }
    }

    mutating func cursor() throws -> StreamCursor {
        switch try u8() {
        case 0: .beforeFirst
        case 1: .at(try u64())
        case let tag: throw RelayWireCodecError.invalidEnumTag(tag)
        }
    }

    mutating func certificate() throws -> RelayV2SignedCertificate {
        let subjectPubkey = try raw(count: 32)
        let role: RelayV2CertRole
        switch try u8() {
        case 0: role = .link
        case 1: role = .data
        case let tag: throw RelayWireCodecError.invalidEnumTag(tag)
        }
        let generation = try u64()
        let rootKeyId = try raw(count: 16)
        let trustEpoch = try u64()
        let notAfterMs: UInt64?
        switch try u8() {
        case 0: notAfterMs = nil
        case 1: notAfterMs = try u64()
        case let tag: throw RelayWireCodecError.invalidEnumTag(tag)
        }
        return RelayV2SignedCertificate(
            subjectPubkey: subjectPubkey,
            certRole: role,
            generation: generation,
            rootKeyId: rootKeyId,
            trustEpoch: trustEpoch,
            notAfterMs: notAfterMs,
            signature: try raw(count: 64)
        )
    }

    mutating func grant() throws -> RelayV2Grant {
        RelayV2Grant(
            machineRoute: try raw(count: 16),
            deviceRoute: try raw(count: 16),
            deviceSignPubkey: try raw(count: 32),
            grantSerial: try u64(),
            rootKeyId: try raw(count: 16),
            trustEpoch: try u64(),
            signature: try raw(count: 64)
        )
    }

    mutating func revocation() throws -> RelayV2DeviceRevocation {
        RelayV2DeviceRevocation(
            machineRoute: try raw(count: 16),
            deviceRoute: try raw(count: 16),
            grantSerial: try u64(),
            rootKeyId: try raw(count: 16),
            trustEpoch: try u64(),
            signature: try raw(count: 64)
        )
    }
}

private struct RelayJSONCodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int?

    init(_ stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(stringValue: String) {
        self.init(stringValue)
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func relayKey(_ value: String) -> RelayJSONCodingKey {
    RelayJSONCodingKey(value)
}

private func rejectRelayUnknownKeys(_ decoder: Decoder, allowed: Set<String>) throws {
    let container = try decoder.container(keyedBy: RelayJSONCodingKey.self)
    if let unknown = container.allKeys.first(where: { !allowed.contains($0.stringValue) }) {
        throw DecodingError.dataCorruptedError(
            forKey: unknown,
            in: container,
            debugDescription: "unknown field \(unknown.stringValue)"
        )
    }
}

private extension CaseIterable where Self: CodingKey {
    static var all: Set<String> {
        Set(allCases.map(\.stringValue))
    }
}

private let relayFramePayloadKeys: [String: Set<String>] = [
    "hello": ["protocolVersion"],
    "challenge": ["relayServerId", "connectionInstance", "challengeNonce"],
    "authenticate": ["proof", "signature"],
    "authenticated": ["heartbeatIntervalSecs"],
    "openPairRoute": ["machineRoute", "pairRoute", "absoluteExpiryMs"],
    "pairRouteOpened": ["machineRoute", "pairRoute", "absoluteExpiryMs"],
    "pairData": ["pairRoute", "sealedBlob"],
    "closePairRoute": ["machineRoute", "pairRoute"],
    "pairRouteClosed": ["pairRoute", "outcome"],
    "registerStream": ["machineRoute", "streamRoute", "generation"],
    "publish": ["streamRoute", "generation", "streamSeq", "sealedBlob"],
    "subscribe": ["streamRoute", "generation", "cursor"],
    "unsubscribe": ["streamRoute", "generation"],
    "ack": ["streamRoute", "generation", "upToSeq"],
    "gap": ["streamRoute", "generation", "needStreamSeq", "oldestStreamSeq"],
    "replayComplete": ["streamRoute", "generation", "currentCursor"],
    "send": ["deviceRoute", "requestRoute", "sealedBlob"],
    "reply": ["deviceRoute", "requestRoute", "sealedBlob"],
    "installGrant": ["grant"],
    "grantCommitted": ["deviceRoute", "grantSerial", "grantHash"],
    "revokeDevice": ["revocation"],
    "revocationCommitted": ["deviceRoute", "grantSerial", "signedRevocation"],
    "retireMachine": ["machineRoute", "trustEpoch", "signature"],
    "ping": ["nonce"],
    "pong": ["nonce"],
    "routeAccepted": ["accepted"],
    "error": ["code", "message", "inReplyTo"],
    "serverRestarting": ["drainDeadlineMs"],
]
