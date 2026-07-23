import CryptoKit
import Foundation
import XCTest
@testable import AgentDeckRelayClient

final class RelayCryptoVectorTests: XCTestCase {
    func testSealedPayloadInnerCodecRejectsMalformedCorpus() throws {
        let valid = try RelayCrypto.encodeSealedPayload(
            RelaySealedPayloadV1(
                formatVersion: 1,
                payloadKind: .transferPart,
                payload: Data([0xCA, 0xFE])
            )
        )
        XCTAssertEqual(try RelayCrypto.decodeSealedPayload(valid).payloadKind, .transferPart)

        var badMagic = valid
        badMagic[0] ^= 0xFF
        var badVersion = valid
        badVersion[6] = 2
        var badKind = valid
        badKind[7] = 0xFF
        var declaredShort = valid
        declaredShort[11] = 1
        var declaredLong = valid
        declaredLong[11] = 3
        var trailing = valid
        trailing.append(0)

        for malformed in [
            Data(), badMagic, badVersion, badKind, declaredShort, declaredLong, trailing,
        ] {
            XCTAssertThrowsError(try RelayCrypto.decodeSealedPayload(malformed)) { error in
                XCTAssertEqual(error as? RelayCryptoError, .badCiphertext)
            }
        }
    }

    func testCanonicalTBSAADAndSHA256MatchSharedVectors() throws {
        let vectors = try loadVectors()
        let tbsVector = try section("tbs_canonical", in: vectors)
        let aadVector = try section("outer_context_aad", in: vectors)
        let shaVector = try section("sha256", in: vectors)

        let encodedTBS = try CanonicalCodec.encode(sampleTBS())
        XCTAssertEqual(encodedTBS, try data("encodedHex", in: tbsVector))
        XCTAssertEqual(CanonicalCodec.sha256(encodedTBS), try data("sha256Hex", in: tbsVector))

        let aad = try CanonicalCodec.encodeAAD(sampleOuterContext())
        XCTAssertEqual(aad, try data("aadHex", in: aadVector))
        XCTAssertEqual(
            CanonicalCodec.sha256(try data("inputHex", in: shaVector)),
            try data("digestHex", in: shaVector)
        )
    }

    func testEd25519SignVerifyAndTamperMatchSharedVector() throws {
        let vector = try section("ed25519", in: loadVectors())
        let privateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: data("seedHex", in: vector)
        )
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, try data("publicKeyHex", in: vector))

        let rustSignature = try data("signatureHex", in: vector)
        XCTAssertTrue(RelayCrypto.verify(rustSignature, tbs: sampleTBS(), key: privateKey.publicKey))

        // CryptoKit 当前系统实现会随机化 Ed25519 signature；互操作门禁验证语义，
        // 不要求 Swift sign 复现 Rust deterministic signature bytes。
        let signature = try RelayCrypto.sign(sampleTBS(), key: privateKey)
        XCTAssertTrue(RelayCrypto.verify(signature, tbs: sampleTBS(), key: privateKey.publicKey))

        var tampered = rustSignature
        tampered[0] ^= 1
        XCTAssertFalse(RelayCrypto.verify(tampered, tbs: sampleTBS(), key: privateKey.publicKey))
        var changedTBS = sampleTBS()
        changedTBS.serialOrGeneration = 10
        XCTAssertFalse(RelayCrypto.verify(rustSignature, tbs: changedTBS, key: privateKey.publicKey))
    }

    func testChaChaPolyTypeStateRoundTripMatchesSharedVectors() throws {
        let vectors = try loadVectors()
        let aead = try section("chacha20poly1305", in: vectors)
        let sealedVector = try section("sealed_blob", in: vectors)
        let privateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: data("seedHex", in: section("ed25519", in: vectors))
        )
        let sendingKey = try sampleSendingKey(rawKey: data("keyHex", in: aead))

        let unsigned = try RelayCrypto.sealSymmetric(
            data("plaintextHex", in: aead),
            key: sendingKey,
            context: sampleOuterContext(),
            counter: 0x0102_0304_0506_0708
        )
        XCTAssertEqual(unsigned.nonce, try data("nonceHex", in: aead))
        XCTAssertEqual(unsigned.ciphertext, try data("ciphertextHex", in: aead))
        XCTAssertEqual(
            try CanonicalCodec.sealedBlobTBS(unsigned, context: sampleOuterContext()),
            try data("tbsHex", in: sealedVector)
        )

        let signed = SignedSealedBlobV1(
            inner: unsigned,
            signature: try data("signatureHex", in: sealedVector)
        )
        let verified = try RelayCrypto.verifySealed(
            signed,
            key: privateKey.publicKey,
            context: sampleOuterContext()
        )
        let receivingKey = try sampleReceivingKey(rawKey: data("keyHex", in: aead))
        let opened = try RelayCrypto.openSealedPayload(
            verified,
            key: receivingKey,
            context: sampleOuterContext()
        )
        XCTAssertEqual(opened.payloadKind, .conversationEvent)
        XCTAssertEqual(opened.payload, try data("plaintextHex", in: aead))

        let swiftSigned = try RelayCrypto.signSealed(
            unsigned,
            key: privateKey,
            context: sampleOuterContext()
        )
        _ = try RelayCrypto.verifySealed(
            swiftSigned,
            key: privateKey.publicKey,
            context: sampleOuterContext()
        )
    }

    func testSealedBlobTamperReturnsTypedFailures() throws {
        let vectors = try loadVectors()
        let aead = try section("chacha20poly1305", in: vectors)
        let privateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: data("seedHex", in: section("ed25519", in: vectors))
        )
        let unsigned = try RelayCrypto.sealSymmetric(
            data("plaintextHex", in: aead),
            key: sampleSendingKey(rawKey: data("keyHex", in: aead)),
            context: sampleOuterContext(),
            counter: 0x0102_0304_0506_0708
        )
        let signed = try RelayCrypto.signSealed(unsigned, key: privateKey, context: sampleOuterContext())

        var badSignature = signed.signature
        badSignature[0] ^= 1
        XCTAssertThrowsError(
            try RelayCrypto.verifySealed(
                SignedSealedBlobV1(inner: signed.inner, signature: badSignature),
                key: privateKey.publicKey,
                context: sampleOuterContext()
            )
        ) { error in
            XCTAssertEqual(error as? RelayCryptoError, .badSignature)
        }

        var badCiphertext = unsigned.ciphertext
        badCiphertext[0] ^= 1
        let selfConsistentTamper = UnsignedSealedBlobV1(
            formatVersion: unsigned.formatVersion,
            keyID: unsigned.keyID,
            keyEpoch: unsigned.keyEpoch,
            keyDirectoryRevision: unsigned.keyDirectoryRevision,
            nonce: unsigned.nonce,
            ciphertext: badCiphertext
        )
        let resigned = try RelayCrypto.signSealed(
            selfConsistentTamper,
            key: privateKey,
            context: sampleOuterContext()
        )
        let reverified = try RelayCrypto.verifySealed(
            resigned,
            key: privateKey.publicKey,
            context: sampleOuterContext()
        )
        XCTAssertThrowsError(
            try RelayCrypto.openSymmetric(
                reverified,
                key: sampleReceivingKey(rawKey: data("keyHex", in: aead)),
                context: sampleOuterContext()
            )
        ) { error in
            XCTAssertEqual(error as? RelayCryptoError, .badCiphertext)
        }
    }

    func testRustFixedHPKEOpensInCryptoKitAndRejectsTamper() throws {
        let vector = try section("hpke_base_kat", in: loadVectors())
        let recipient = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: data("recipientPrivHex", in: vector)
        )
        let envelope = HPKEEnvelopeV1(
            enc: try data("encHex", in: vector),
            ciphertext: try data("ciphertextHex", in: vector)
        )
        XCTAssertEqual(
            try RelayCrypto.openHPKE(
                envelope,
                recipient: recipient,
                info: data("infoHex", in: vector),
                aad: data("aadHex", in: vector)
            ),
            try data("plaintextHex", in: vector)
        )

        var tampered = envelope.ciphertext
        tampered[0] ^= 1
        XCTAssertThrowsError(
            try RelayCrypto.openHPKE(
                HPKEEnvelopeV1(enc: envelope.enc, ciphertext: tampered),
                recipient: recipient,
                info: data("infoHex", in: vector),
                aad: data("aadHex", in: vector)
            )
        ) { error in
            XCTAssertEqual(error as? RelayCryptoError, .badCiphertext)
        }
    }

    func testSwiftHPKESealOpensInRustProbe() throws {
        let vector = try section("hpke_base_kat", in: loadVectors())
        let generated: ProbeKeyPair = try decodeProbe(runProbe(command: "generate"))
        let publicKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: Data(hex: generated.recipientPublicKeyHex)
        )
        let plaintext = Data("swift-hpke-to-rust".utf8)
        let info = try data("infoHex", in: vector)
        let aad = try data("aadHex", in: vector)
        let envelope = try RelayCrypto.sealHPKE(
            plaintext,
            recipient: publicKey,
            info: info,
            aad: aad
        )
        let request = ProbeOpenRequest(
            recipientPrivateKeyHex: generated.recipientPrivateKeyHex,
            infoHex: info.hex,
            aadHex: aad.hex,
            encHex: envelope.enc.hex,
            ciphertextHex: envelope.ciphertext.hex
        )
        let opened: ProbeOpenResponse = try decodeProbe(
            runProbe(command: "open", stdin: try JSONEncoder().encode(request))
        )
        XCTAssertEqual(Data(hex: opened.plaintextHex), plaintext)
    }

    func testSwiftEd25519SignatureVerifiesInRustProbe() throws {
        let vector = try section("ed25519", in: loadVectors())
        let privateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: data("seedHex", in: vector)
        )
        let message = try CanonicalCodec.encode(sampleTBS())
        let signature = try RelayCrypto.sign(sampleTBS(), key: privateKey)
        let request = ProbeSignatureRequest(
            publicKeyHex: privateKey.publicKey.rawRepresentation.hex,
            messageHex: message.hex,
            signatureHex: signature.hex
        )
        let response: ProbeSignatureResponse = try decodeProbe(
            runProbe(command: "verify-signature", stdin: try JSONEncoder().encode(request))
        )
        XCTAssertTrue(response.valid)
    }

    func testSecretDebugDescriptionsAreRedacted() throws {
        let rawKey = Data(repeating: 0xA5, count: 32)
        let sending = try sampleSendingKey(rawKey: rawKey)
        let receiving = try sampleReceivingKey(rawKey: rawKey)
        for debug in [String(reflecting: sending), String(reflecting: receiving)] {
            XCTAssertTrue(debug.contains("<redacted>"), debug)
            XCTAssertFalse(debug.lowercased().contains(rawKey.hex), debug)
        }
    }

    private func sampleTBS() -> ToBeSignedV1 {
        ToBeSignedV1(
            objectType: .relayGrant,
            signatureFormatVersion: 1,
            relayProtocolVersion: 2,
            runtimeProtocolVersion: 5,
            e2eeFormatVersion: 1,
            relayServerID: Data(repeating: 0x88, count: 16),
            machineRoute: Data(repeating: 0x11, count: 16),
            deviceRoute: Data(repeating: 0x22, count: 16),
            streamRoute: nil,
            requestRoute: nil,
            streamGeneration: nil,
            streamCursor: nil,
            roleScope: "device",
            signingKeyFingerprint: Data(repeating: 0x0F, count: 32),
            rootKeyID: Data(repeating: 0x77, count: 16),
            trustEpoch: 3,
            serialOrGeneration: 9,
            notAfterMS: nil,
            signedObjectSHA256: Data(repeating: 0x0E, count: 32)
        )
    }

    private func sampleOuterContext() -> OuterContextV1 {
        OuterContextV1(
            frameKind: .conversationPublish,
            relayProtocolVersion: 2,
            e2eeFormatVersion: 1,
            machineRoute: Data(repeating: 0x11, count: 16),
            deviceRoute: nil,
            streamRoute: Data(repeating: 0x33, count: 16),
            requestRoute: nil,
            streamGeneration: Data(repeating: 0x66, count: 16),
            streamCursor: .at(7),
            streamSeq: 7,
            messageKeyEpoch: 4
        )
    }

    private func sampleSendingKey(rawKey: Data) throws -> AeadSendingKey {
        try AeadSendingKey(
            keyID: KeyIDV1(purpose: .conversationDEK, epoch: 4),
            epoch: 4,
            keyDirectoryRevision: 2,
            noncePrefix: Data([0xAA, 0xBB, 0xCC, 0xDD]),
            payloadKind: .conversationEvent,
            rawKey: rawKey
        )
    }

    private func sampleReceivingKey(rawKey: Data) throws -> AeadReceivingKey {
        try AeadReceivingKey(
            keyID: KeyIDV1(purpose: .conversationDEK, epoch: 4),
            epoch: 4,
            rawKey: rawKey
        )
    }

    private var repoRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func loadVectors() throws -> [String: Any] {
        let url = repoRoot
            .appendingPathComponent("protocol")
            .appendingPathComponent("agentdeck")
            .appendingPathComponent("crypto-vectors-v1.json")
        return try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        )
    }

    private func section(_ name: String, in vectors: [String: Any]) throws -> [String: Any] {
        try XCTUnwrap(vectors[name] as? [String: Any], "missing vector section \(name)")
    }

    private func data(_ key: String, in section: [String: Any]) throws -> Data {
        Data(hex: try XCTUnwrap(section[key] as? String, "missing vector field \(key)"))
    }

    private func runProbe(command: String, stdin: Data? = nil) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [
            "cargo", "run", "--quiet", "-p", "agentdeck-crypto",
            "--example", "hpke_probe", "--", command,
        ]
        process.currentDirectoryURL = repoRoot
        let stdout = Pipe()
        let stderr = Pipe()
        let input = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        process.standardInput = input
        try process.run()
        if let stdin {
            input.fileHandleForWriting.write(stdin)
        }
        input.fileHandleForWriting.closeFile()
        process.waitUntilExit()
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        let errorOutput = stderr.fileHandleForReading.readDataToEndOfFile()
        XCTAssertEqual(
            process.terminationStatus,
            0,
            String(data: errorOutput, encoding: .utf8) ?? "hpke_probe failed"
        )
        return output
    }

    private func decodeProbe<T: Decodable>(_ data: Data) throws -> T {
        try JSONDecoder().decode(T.self, from: data)
    }
}

private struct ProbeKeyPair: Decodable {
    let recipientPrivateKeyHex: String
    let recipientPublicKeyHex: String
}

private struct ProbeOpenRequest: Encodable {
    let recipientPrivateKeyHex: String
    let infoHex: String
    let aadHex: String
    let encHex: String
    let ciphertextHex: String
}

private struct ProbeOpenResponse: Decodable {
    let plaintextHex: String
}

private struct ProbeSignatureRequest: Encodable {
    let publicKeyHex: String
    let messageHex: String
    let signatureHex: String
}

private struct ProbeSignatureResponse: Decodable {
    let valid: Bool
}

private extension Data {
    init(hex: String) {
        precondition(hex.count.isMultiple(of: 2), "hex length must be even")
        self.init(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
    }

    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
