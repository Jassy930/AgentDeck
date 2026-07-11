import CryptoKit
import Foundation

// MARK: - Canonical mirror DTOs

public enum RelayCryptoError: Error, Equatable, Sendable {
    case badSignature
    case badCiphertext
    case invalidKey(field: String)
    case invalidLength(field: String, expected: Int, actual: Int)
    case lengthOverflow(field: String)
    case hpkeFailure
    case sealFailure
}

public enum SignedObjectType: String, Codable, Sendable {
    case linkCert
    case dataCert
    case relayGrant
    case deviceAuthorization
    case deviceRevocation
    case retireMachine
    case downlinkData
    case uplinkRequest
    case pairingProof

    var canonicalTag: UInt8 {
        switch self {
        case .linkCert: 0
        case .dataCert: 1
        case .relayGrant: 2
        case .deviceAuthorization: 3
        case .deviceRevocation: 4
        case .retireMachine: 5
        case .downlinkData: 6
        case .uplinkRequest: 7
        case .pairingProof: 8
        }
    }
}

public enum OuterFrameKind: String, Codable, Sendable {
    case catalogPublish
    case conversationPublish
    case directedReply
    case uplinkSend
    case pairRequest
    case pairResponse
    case keyUpdate

    var canonicalTag: UInt8 {
        switch self {
        case .catalogPublish: 0
        case .conversationPublish: 1
        case .directedReply: 2
        case .uplinkSend: 3
        case .pairRequest: 4
        case .pairResponse: 5
        case .keyUpdate: 6
        }
    }
}

public enum StreamCursor: Equatable, Sendable {
    case beforeFirst
    case at(UInt64)
}

public enum KeyPurpose: String, Codable, Sendable {
    case catalog
    case conversationDEK = "conversationDek"
    case deviceCommandTx
    case deviceReplyTx

    var canonicalTag: UInt8 {
        switch self {
        case .catalog: 0
        case .conversationDEK: 1
        case .deviceCommandTx: 2
        case .deviceReplyTx: 3
        }
    }
}

public struct KeyIDV1: Equatable, Sendable {
    public var purpose: KeyPurpose
    public var epoch: UInt64

    public init(purpose: KeyPurpose, epoch: UInt64) {
        self.purpose = purpose
        self.epoch = epoch
    }
}

public enum SealedPayloadKind: String, Codable, Sendable {
    case catalogSnapshot
    case catalogDelta
    case conversationSnapshot
    case conversationEvent
    case commandRequest
    case commandReceipt
    case approvalDecision
    case approvalReceipt
    case backfillChunk
    case keyUpdate
    case pairingMessage

    var canonicalTag: UInt8 {
        switch self {
        case .catalogSnapshot: 0
        case .catalogDelta: 1
        case .conversationSnapshot: 2
        case .conversationEvent: 3
        case .commandRequest: 4
        case .commandReceipt: 5
        case .approvalDecision: 6
        case .approvalReceipt: 7
        case .backfillChunk: 8
        case .keyUpdate: 9
        case .pairingMessage: 10
        }
    }
}

public struct ToBeSignedV1: Equatable, Sendable {
    public var objectType: SignedObjectType
    public var signatureFormatVersion: UInt16
    public var relayProtocolVersion: UInt16
    public var runtimeProtocolVersion: UInt16
    public var e2eeFormatVersion: UInt16
    public var relayServerID: Data
    public var machineRoute: Data
    public var deviceRoute: Data?
    public var streamRoute: Data?
    public var requestRoute: Data?
    public var streamGeneration: Data?
    public var streamCursor: StreamCursor?
    public var roleScope: String
    public var signingKeyFingerprint: Data
    public var rootKeyID: Data
    public var trustEpoch: UInt64
    public var serialOrGeneration: UInt64
    public var notAfterMS: UInt64?
    public var signedObjectSHA256: Data

    public init(
        objectType: SignedObjectType,
        signatureFormatVersion: UInt16,
        relayProtocolVersion: UInt16,
        runtimeProtocolVersion: UInt16,
        e2eeFormatVersion: UInt16,
        relayServerID: Data,
        machineRoute: Data,
        deviceRoute: Data?,
        streamRoute: Data?,
        requestRoute: Data?,
        streamGeneration: Data?,
        streamCursor: StreamCursor?,
        roleScope: String,
        signingKeyFingerprint: Data,
        rootKeyID: Data,
        trustEpoch: UInt64,
        serialOrGeneration: UInt64,
        notAfterMS: UInt64?,
        signedObjectSHA256: Data
    ) {
        self.objectType = objectType
        self.signatureFormatVersion = signatureFormatVersion
        self.relayProtocolVersion = relayProtocolVersion
        self.runtimeProtocolVersion = runtimeProtocolVersion
        self.e2eeFormatVersion = e2eeFormatVersion
        self.relayServerID = relayServerID
        self.machineRoute = machineRoute
        self.deviceRoute = deviceRoute
        self.streamRoute = streamRoute
        self.requestRoute = requestRoute
        self.streamGeneration = streamGeneration
        self.streamCursor = streamCursor
        self.roleScope = roleScope
        self.signingKeyFingerprint = signingKeyFingerprint
        self.rootKeyID = rootKeyID
        self.trustEpoch = trustEpoch
        self.serialOrGeneration = serialOrGeneration
        self.notAfterMS = notAfterMS
        self.signedObjectSHA256 = signedObjectSHA256
    }
}

public struct OuterContextV1: Equatable, Sendable {
    public var frameKind: OuterFrameKind
    public var relayProtocolVersion: UInt16
    public var e2eeFormatVersion: UInt16
    public var machineRoute: Data?
    public var deviceRoute: Data?
    public var streamRoute: Data?
    public var requestRoute: Data?
    public var streamGeneration: Data?
    public var streamCursor: StreamCursor?
    public var streamSeq: UInt64?
    public var messageKeyEpoch: UInt64

    public init(
        frameKind: OuterFrameKind,
        relayProtocolVersion: UInt16,
        e2eeFormatVersion: UInt16,
        machineRoute: Data?,
        deviceRoute: Data?,
        streamRoute: Data?,
        requestRoute: Data?,
        streamGeneration: Data?,
        streamCursor: StreamCursor?,
        streamSeq: UInt64?,
        messageKeyEpoch: UInt64
    ) {
        self.frameKind = frameKind
        self.relayProtocolVersion = relayProtocolVersion
        self.e2eeFormatVersion = e2eeFormatVersion
        self.machineRoute = machineRoute
        self.deviceRoute = deviceRoute
        self.streamRoute = streamRoute
        self.requestRoute = requestRoute
        self.streamGeneration = streamGeneration
        self.streamCursor = streamCursor
        self.streamSeq = streamSeq
        self.messageKeyEpoch = messageKeyEpoch
    }
}

public struct HPKEEnvelopeV1: Equatable, Sendable {
    public var enc: Data
    public var ciphertext: Data

    public init(enc: Data, ciphertext: Data) {
        self.enc = enc
        self.ciphertext = ciphertext
    }
}

public struct UnsignedSealedBlobV1: Equatable, Sendable {
    public var formatVersion: UInt16
    public var payloadKind: SealedPayloadKind
    public var keyID: KeyIDV1
    public var keyEpoch: UInt64
    public var keyDirectoryRevision: UInt64
    public var nonce: Data
    public var ciphertext: Data

    public init(
        formatVersion: UInt16,
        payloadKind: SealedPayloadKind,
        keyID: KeyIDV1,
        keyEpoch: UInt64,
        keyDirectoryRevision: UInt64,
        nonce: Data,
        ciphertext: Data
    ) {
        self.formatVersion = formatVersion
        self.payloadKind = payloadKind
        self.keyID = keyID
        self.keyEpoch = keyEpoch
        self.keyDirectoryRevision = keyDirectoryRevision
        self.nonce = nonce
        self.ciphertext = ciphertext
    }
}

public struct SignedSealedBlobV1: Equatable, Sendable {
    public var inner: UnsignedSealedBlobV1
    public var signature: Data

    public init(inner: UnsignedSealedBlobV1, signature: Data) {
        self.inner = inner
        self.signature = signature
    }
}

// MARK: - Canonical encoding

public enum CanonicalCodec {
    public static func encode(_ value: ToBeSignedV1) throws -> Data {
        var encoder = Encoder()
        encoder.domain("AgentDeck/ToBeSignedV1\0")
        encoder.u8(value.objectType.canonicalTag)
        encoder.u16(value.signatureFormatVersion)
        encoder.u16(value.relayProtocolVersion)
        encoder.u16(value.runtimeProtocolVersion)
        encoder.u16(value.e2eeFormatVersion)
        try encoder.bytes(value.relayServerID, field: "relayServerID", exactLength: 16)
        try encoder.bytes(value.machineRoute, field: "machineRoute", exactLength: 16)
        try encoder.optionalID(value.deviceRoute, field: "deviceRoute")
        try encoder.optionalID(value.streamRoute, field: "streamRoute")
        try encoder.optionalID(value.requestRoute, field: "requestRoute")
        try encoder.optionalID(value.streamGeneration, field: "streamGeneration")
        encoder.optionalCursor(value.streamCursor)
        try encoder.string(value.roleScope, field: "roleScope")
        try encoder.bytes(
            value.signingKeyFingerprint,
            field: "signingKeyFingerprint",
            exactLength: 32
        )
        try encoder.bytes(value.rootKeyID, field: "rootKeyID", exactLength: 16)
        encoder.u64(value.trustEpoch)
        encoder.u64(value.serialOrGeneration)
        encoder.optionalU64(value.notAfterMS)
        try encoder.bytes(value.signedObjectSHA256, field: "signedObjectSHA256", exactLength: 32)
        return encoder.finish()
    }

    public static func encodeAAD(_ context: OuterContextV1) throws -> Data {
        var encoder = Encoder()
        encoder.domain("AgentDeck/OuterContextV1\0")
        encoder.u8(context.frameKind.canonicalTag)
        encoder.u16(context.relayProtocolVersion)
        encoder.u16(context.e2eeFormatVersion)
        try encoder.optionalID(context.machineRoute, field: "machineRoute")
        try encoder.optionalID(context.deviceRoute, field: "deviceRoute")
        try encoder.optionalID(context.streamRoute, field: "streamRoute")
        try encoder.optionalID(context.requestRoute, field: "requestRoute")
        try encoder.optionalID(context.streamGeneration, field: "streamGeneration")
        encoder.optionalCursor(context.streamCursor)
        encoder.optionalU64(context.streamSeq)
        encoder.u64(context.messageKeyEpoch)
        return encoder.finish()
    }

    public static func sealedBlobTBS(
        _ blob: UnsignedSealedBlobV1,
        context: OuterContextV1
    ) throws -> Data {
        guard blob.nonce.count == 12 else {
            throw RelayCryptoError.invalidLength(
                field: "nonce",
                expected: 12,
                actual: blob.nonce.count
            )
        }
        var encoder = Encoder()
        encoder.domain("AgentDeck/SealedBlobTbsV1\0")
        try encoder.bytes(encodeAAD(context), field: "outerContextAAD")
        encoder.u16(blob.formatVersion)
        encoder.u8(blob.payloadKind.canonicalTag)
        encoder.u8(blob.keyID.purpose.canonicalTag)
        encoder.u64(blob.keyID.epoch)
        encoder.u64(blob.keyEpoch)
        encoder.u64(blob.keyDirectoryRevision)
        try encoder.bytes(blob.nonce, field: "nonce")
        try encoder.bytes(sha256(blob.ciphertext), field: "ciphertextSHA256")
        return encoder.finish()
    }

    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}

private struct Encoder {
    private var output = Data()

    mutating func domain(_ value: String) {
        output.append(contentsOf: value.utf8)
    }

    mutating func u8(_ value: UInt8) {
        output.append(value)
    }

    mutating func u16(_ value: UInt16) {
        appendBigEndian(value)
    }

    mutating func u64(_ value: UInt64) {
        appendBigEndian(value)
    }

    mutating func bytes(
        _ value: Data,
        field: String,
        exactLength: Int? = nil
    ) throws {
        if let exactLength, value.count != exactLength {
            throw RelayCryptoError.invalidLength(
                field: field,
                expected: exactLength,
                actual: value.count
            )
        }
        guard let count = UInt32(exactly: value.count) else {
            throw RelayCryptoError.lengthOverflow(field: field)
        }
        appendBigEndian(count)
        output.append(value)
    }

    mutating func string(_ value: String, field: String) throws {
        try bytes(Data(value.utf8), field: field)
    }

    mutating func optionalID(_ value: Data?, field: String) throws {
        guard let value else {
            u8(0)
            return
        }
        guard value.count == 16 else {
            throw RelayCryptoError.invalidLength(field: field, expected: 16, actual: value.count)
        }
        u8(1)
        output.append(value)
    }

    mutating func optionalU64(_ value: UInt64?) {
        guard let value else {
            u8(0)
            return
        }
        u8(1)
        u64(value)
    }

    mutating func optionalCursor(_ value: StreamCursor?) {
        guard let value else {
            u8(0)
            return
        }
        u8(1)
        switch value {
        case .beforeFirst:
            u8(0)
        case .at(let cursor):
            u8(1)
            u64(cursor)
        }
    }

    func finish() -> Data {
        output
    }

    private mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { bytes in
            output.append(contentsOf: bytes)
        }
    }
}
