import CryptoKit
import Foundation

public struct AeadSendingKey: Sendable, CustomDebugStringConvertible {
    public let keyID: KeyIDV1
    public let epoch: UInt64
    public let keyDirectoryRevision: UInt64
    public let noncePrefix: Data
    public let payloadKind: SealedPayloadKind
    let symmetricKey: SymmetricKey

    /// Production constructor：从 256-bit key 以 domain-separated HMAC 派生 nonce prefix。
    public init(
        keyID: KeyIDV1,
        epoch: UInt64,
        keyDirectoryRevision: UInt64,
        payloadKind: SealedPayloadKind,
        rawKey: Data
    ) throws {
        guard rawKey.count == 32 else {
            throw RelayCryptoError.invalidLength(
                field: "aeadKey",
                expected: 32,
                actual: rawKey.count
            )
        }
        let key = SymmetricKey(data: rawKey)
        let prefix = HMAC<SHA256>.authenticationCode(
            for: Data("AgentDeck/AEADNoncePrefix/v1\0".utf8),
            using: key
        )
        try self.init(
            keyID: keyID,
            epoch: epoch,
            keyDirectoryRevision: keyDirectoryRevision,
            noncePrefix: Data(prefix.prefix(4)),
            payloadKind: payloadKind,
            rawKey: rawKey
        )
    }

    /// 显式 prefix 只供 golden vector / synthetic test 使用。
    init(
        keyID: KeyIDV1,
        epoch: UInt64,
        keyDirectoryRevision: UInt64,
        noncePrefix: Data,
        payloadKind: SealedPayloadKind,
        rawKey: Data
    ) throws {
        guard keyID.epoch == epoch else {
            throw RelayCryptoError.invalidKey(field: "keyID.epoch")
        }
        guard noncePrefix.count == 4 else {
            throw RelayCryptoError.invalidLength(
                field: "noncePrefix",
                expected: 4,
                actual: noncePrefix.count
            )
        }
        guard rawKey.count == 32 else {
            throw RelayCryptoError.invalidLength(
                field: "aeadKey",
                expected: 32,
                actual: rawKey.count
            )
        }
        self.keyID = keyID
        self.epoch = epoch
        self.keyDirectoryRevision = keyDirectoryRevision
        self.noncePrefix = noncePrefix
        self.payloadKind = payloadKind
        symmetricKey = SymmetricKey(data: rawKey)
    }

    /// 在不暴露或复制 raw bytes 的前提下，为同一 key identity 绑定新的 revision/payload
    /// capability。nonce prefix 与 SymmetricKey 保持逐字相同。
    func rebinding(
        keyDirectoryRevision: UInt64,
        payloadKind: SealedPayloadKind
    ) throws -> Self {
        guard keyDirectoryRevision > 0 else {
            throw RelayCryptoError.invalidKey(field: "keyDirectoryRevision")
        }
        return try Self(
            keyID: keyID,
            epoch: epoch,
            keyDirectoryRevision: keyDirectoryRevision,
            noncePrefix: noncePrefix,
            payloadKind: payloadKind,
            symmetricKey: symmetricKey
        )
    }

    private init(
        keyID: KeyIDV1,
        epoch: UInt64,
        keyDirectoryRevision: UInt64,
        noncePrefix: Data,
        payloadKind: SealedPayloadKind,
        symmetricKey: SymmetricKey
    ) throws {
        guard keyID.epoch == epoch,
            keyDirectoryRevision > 0,
            noncePrefix.count == 4
        else {
            throw RelayCryptoError.invalidKey(field: "aead capability rebind")
        }
        self.keyID = keyID
        self.epoch = epoch
        self.keyDirectoryRevision = keyDirectoryRevision
        self.noncePrefix = noncePrefix
        self.payloadKind = payloadKind
        self.symmetricKey = symmetricKey
    }

    public var debugDescription: String {
        "AeadSendingKey(<redacted>)"
    }
}

public struct AeadReceivingKey: Sendable, CustomDebugStringConvertible {
    public let keyID: KeyIDV1
    public let epoch: UInt64
    let symmetricKey: SymmetricKey

    public init(keyID: KeyIDV1, epoch: UInt64, rawKey: Data) throws {
        guard keyID.epoch == epoch else {
            throw RelayCryptoError.invalidKey(field: "keyID.epoch")
        }
        guard rawKey.count == 32 else {
            throw RelayCryptoError.invalidLength(
                field: "aeadKey",
                expected: 32,
                actual: rawKey.count
            )
        }
        self.keyID = keyID
        self.epoch = epoch
        symmetricKey = SymmetricKey(data: rawKey)
    }

    public var debugDescription: String {
        "AeadReceivingKey(<redacted>)"
    }
}

/// 仅能由 `RelayCrypto.verifySealed` 构造；wire 解码不能伪造“已验签”状态。
public struct VerifiedSealedBlobV1: Equatable, Sendable {
    fileprivate let inner: SignedSealedBlobV1

    fileprivate init(inner: SignedSealedBlobV1) {
        self.inner = inner
    }

    public var sealed: SignedSealedBlobV1 { inner }
}

public enum RelayCrypto {
    public static func openHPKE(
        _ envelope: HPKEEnvelopeV1,
        recipient: Curve25519.KeyAgreement.PrivateKey,
        info: Data,
        aad: Data
    ) throws -> Data {
        var hpkeRecipient: HPKE.Recipient
        do {
            hpkeRecipient = try HPKE.Recipient(
                privateKey: recipient,
                ciphersuite: .Curve25519_SHA256_ChachaPoly,
                info: info,
                encapsulatedKey: envelope.enc
            )
        } catch {
            throw RelayCryptoError.hpkeFailure
        }
        do {
            return try hpkeRecipient.open(envelope.ciphertext, authenticating: aad)
        } catch {
            throw RelayCryptoError.badCiphertext
        }
    }

    public static func sealHPKE(
        _ plaintext: Data,
        recipient: Curve25519.KeyAgreement.PublicKey,
        info: Data,
        aad: Data
    ) throws -> HPKEEnvelopeV1 {
        do {
            var sender = try HPKE.Sender(
                recipientKey: recipient,
                ciphersuite: .Curve25519_SHA256_ChachaPoly,
                info: info
            )
            let ciphertext = try sender.seal(plaintext, authenticating: aad)
            return HPKEEnvelopeV1(
                enc: normalized(sender.encapsulatedKey),
                ciphertext: normalized(ciphertext)
            )
        } catch {
            throw RelayCryptoError.hpkeFailure
        }
    }

    public static func sealSymmetric(
        _ plaintext: Data,
        key: AeadSendingKey,
        context: OuterContextV1,
        counter: UInt64
    ) throws -> UnsignedSealedBlobV1 {
        var nonce = key.noncePrefix
        appendBigEndian(counter, to: &nonce)
        let aad = try CanonicalCodec.encodeAAD(context)
        do {
            let sealedPayload = try encodeSealedPayload(
                RelaySealedPayloadV1(
                    formatVersion: 1,
                    payloadKind: key.payloadKind,
                    payload: plaintext
                )
            )
            let sealed = try ChaChaPoly.seal(
                sealedPayload,
                using: key.symmetricKey,
                nonce: ChaChaPoly.Nonce(data: nonce),
                authenticating: aad
            )
            // CryptoKit 的 ciphertext Data 可能保留 combined slice 的非零 startIndex；
            // 复制进新 buffer，保证公开 DTO 是从 0 开始的独立 bytes。
            var ciphertext = Data()
            ciphertext.reserveCapacity(sealed.ciphertext.count + sealed.tag.count)
            ciphertext.append(contentsOf: sealed.ciphertext)
            ciphertext.append(sealed.tag)
            return UnsignedSealedBlobV1(
                formatVersion: 1,
                keyID: key.keyID,
                keyEpoch: key.epoch,
                keyDirectoryRevision: key.keyDirectoryRevision,
                nonce: nonce,
                ciphertext: ciphertext
            )
        } catch {
            throw RelayCryptoError.sealFailure
        }
    }

    public static func signSealed(
        _ blob: UnsignedSealedBlobV1,
        key: Curve25519.Signing.PrivateKey,
        context: OuterContextV1
    ) throws -> SignedSealedBlobV1 {
        let tbs = try CanonicalCodec.sealedBlobTBS(blob, context: context)
        do {
            return SignedSealedBlobV1(inner: blob, signature: try key.signature(for: tbs))
        } catch {
            throw RelayCryptoError.sealFailure
        }
    }

    public static func verifySealed(
        _ blob: SignedSealedBlobV1,
        key: Curve25519.Signing.PublicKey,
        context: OuterContextV1
    ) throws -> VerifiedSealedBlobV1 {
        let tbs = try CanonicalCodec.sealedBlobTBS(blob.inner, context: context)
        guard key.isValidSignature(blob.signature, for: tbs) else {
            throw RelayCryptoError.badSignature
        }
        return VerifiedSealedBlobV1(inner: blob)
    }

    public static func openSymmetric(
        _ blob: VerifiedSealedBlobV1,
        key: AeadReceivingKey,
        context: OuterContextV1
    ) throws -> Data {
        try openSealedPayload(blob, key: key, context: context).payload
    }

    public static func openSealedPayload(
        _ blob: VerifiedSealedBlobV1,
        key: AeadReceivingKey,
        context: OuterContextV1
    ) throws -> RelaySealedPayloadV1 {
        let sealed = blob.inner.inner
        guard sealed.nonce.count == 12, sealed.ciphertext.count >= 16 else {
            throw RelayCryptoError.badCiphertext
        }
        let tagStart = sealed.ciphertext.count - 16
        let ciphertext = sealed.ciphertext.prefix(tagStart)
        let tag = sealed.ciphertext.suffix(16)
        let aad = try CanonicalCodec.encodeAAD(context)
        do {
            let box = try ChaChaPoly.SealedBox(
                nonce: ChaChaPoly.Nonce(data: sealed.nonce),
                ciphertext: ciphertext,
                tag: tag
            )
            let plaintext = try ChaChaPoly.open(box, using: key.symmetricKey, authenticating: aad)
            return try decodeSealedPayload(plaintext)
        } catch {
            throw RelayCryptoError.badCiphertext
        }
    }

    public static func sign(
        _ tbs: ToBeSignedV1,
        key: Curve25519.Signing.PrivateKey
    ) throws -> Data {
        let message = try CanonicalCodec.encode(tbs)
        do {
            return try key.signature(for: message)
        } catch {
            throw RelayCryptoError.sealFailure
        }
    }

    public static func verify(
        _ signature: Data,
        tbs: ToBeSignedV1,
        key: Curve25519.Signing.PublicKey
    ) -> Bool {
        guard let message = try? CanonicalCodec.encode(tbs) else {
            return false
        }
        return key.isValidSignature(signature, for: message)
    }

    private static func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { bytes in
            data.append(contentsOf: bytes)
        }
    }

    static func encodeSealedPayload(_ value: RelaySealedPayloadV1) throws -> Data {
        guard value.formatVersion == 1,
            let payloadLength = UInt32(exactly: value.payload.count)
        else {
            throw RelayCryptoError.sealFailure
        }
        var data = Data("ADSP1".utf8)
        appendBigEndian(value.formatVersion, to: &data)
        data.append(value.payloadKind.canonicalTag)
        appendBigEndian(payloadLength, to: &data)
        data.append(value.payload)
        return data
    }

    static func decodeSealedPayload(_ data: Data) throws -> RelaySealedPayloadV1 {
        guard data.count >= 12,
            data.prefix(5) == Data("ADSP1".utf8)
        else {
            throw RelayCryptoError.badCiphertext
        }
        let bytes = [UInt8](data.prefix(12))
        let version = (UInt16(bytes[5]) << 8) | UInt16(bytes[6])
        let payloadLength =
            (UInt32(bytes[8]) << 24)
            | (UInt32(bytes[9]) << 16)
            | (UInt32(bytes[10]) << 8)
            | UInt32(bytes[11])
        guard version == 1,
            let kind = SealedPayloadKind(canonicalTag: bytes[7]),
            Int(payloadLength) == data.count - 12
        else {
            throw RelayCryptoError.badCiphertext
        }
        return RelaySealedPayloadV1(
            formatVersion: version,
            payloadKind: kind,
            payload: Data(data.dropFirst(12))
        )
    }

    private static func normalized(_ data: Data) -> Data {
        var copy = Data()
        copy.reserveCapacity(data.count)
        copy.append(contentsOf: data)
        return copy
    }
}
