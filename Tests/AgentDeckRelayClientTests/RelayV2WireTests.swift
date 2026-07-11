import Foundation
import XCTest
@testable import AgentDeckRelayClient

final class RelayV2WireTests: XCTestCase {
    func testEveryRustOuterVectorMatchesBinaryCodecAndRoundTrips() throws {
        let vectors = try loadRelayVectors()
        let outer = try XCTUnwrap(vectors["outerFrames"] as? [[String: Any]])
        XCTAssertEqual(outer.count, 28)
        XCTAssertEqual(
            Set(outer.compactMap { $0["family"] as? String }),
            ["handshake", "pairing", "stream", "request", "authControl", "runtime"]
        )

        for vector in outer {
            let name = try XCTUnwrap(vector["case"] as? String)
            let input = try JSONSerialization.data(
                withJSONObject: XCTUnwrap(vector["input"])
            )
            let frame = try RelayV2JSONCodec.decodeFrame(input)
            let encoded = try RelayWireCodecV2.encodeFixture(frame)
            XCTAssertEqual(
                encoded,
                Data(hex: try XCTUnwrap(vector["expectedHex"] as? String)),
                "Rust/Swift binary drift for \(name)"
            )
            XCTAssertEqual(
                try RelayWireCodecV2.decode(encoded),
                frame,
                "Swift binary round-trip drift for \(name)"
            )
        }
    }

    func testPublicOutboundFactoriesRequireTypedPayloadsAndMatchP16SealedWire() throws {
        let cryptoVectors = try loadCryptoVectors()
        let sealedVector = try XCTUnwrap(cryptoVectors["sealed_blob"] as? [String: Any])
        let signed = try signedSealedBlob(from: sealedVector)
        let expectedSealed = Data(hex: try XCTUnwrap(sealedVector["wireHex"] as? String))

        let publish = try RelayV2OutboundFrame.publish(
            streamRoute: Data(repeating: 0x33, count: 16),
            generation: Data(repeating: 0x66, count: 16),
            streamSeq: 7,
            sealedBlob: signed
        )
        let publishWire = try RelayWireCodecV2.encode(publish)
        XCTAssertEqual(
            try lengthPrefixedPayload(in: publishWire, after: 5 + 2 + 2 + 16 + 16 + 8),
            expectedSealed
        )

        let send = try RelayV2OutboundFrame.send(
            deviceRoute: Data(repeating: 0x22, count: 16),
            requestRoute: Data(repeating: 0x44, count: 16),
            sealedBlob: signed
        )
        XCTAssertEqual(
            try lengthPrefixedPayload(
                in: RelayWireCodecV2.encode(send),
                after: 5 + 2 + 2 + 16 + 16
            ),
            expectedSealed
        )

        let reply = try RelayV2OutboundFrame.reply(
            deviceRoute: Data(repeating: 0x22, count: 16),
            requestRoute: Data(repeating: 0x44, count: 16),
            sealedBlob: signed
        )
        XCTAssertEqual(
            try lengthPrefixedPayload(
                in: RelayWireCodecV2.encode(reply),
                after: 5 + 2 + 2 + 16 + 16
            ),
            expectedSealed
        )

        let endpoints = try XCTUnwrap(
            try loadRelayVectors()["endpointTypes"] as? [[String: Any]]
        )
        let pairRequest = try XCTUnwrap(
            endpoints.first { ($0["wireType"] as? String) == "PairRequestV1" }
        )
        let pairRequestData = try JSONSerialization.data(
            withJSONObject: XCTUnwrap(pairRequest["value"])
        )
        let typedPairRequest = try RelayV2JSONCodec.decodeEndpoint(
            .pairRequest,
            from: pairRequestData
        )
        let pairData = try RelayV2OutboundFrame.pairData(
            pairRoute: Data(repeating: 0x55, count: 16),
            payload: typedPairRequest
        )
        let encodedPairPayload = try lengthPrefixedPayload(
            in: RelayWireCodecV2.encode(pairData),
            after: 5 + 2 + 2 + 16
        )
        XCTAssertEqual(
            try normalizedJSON(encodedPairPayload),
            try normalizedJSON(pairRequestData)
        )
    }

    func testDirectPublicCodableDecodeCannotBypassRecursiveStrictness() throws {
        let vectors = try loadRelayVectors()
        let outer = try XCTUnwrap(vectors["outerFrames"] as? [[String: Any]])
        let hello = try XCTUnwrap(outer.first { ($0["case"] as? String) == "hello" })
        var helloInput = try XCTUnwrap(hello["input"] as? [String: Any])
        helloInput["unexpected"] = true
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                RelayV2Frame.self,
                from: JSONSerialization.data(withJSONObject: helloInput)
            )
        )

        let install = try XCTUnwrap(
            outer.first { ($0["case"] as? String) == "installGrant" }
        )
        let installInput = try XCTUnwrap(install["input"] as? [String: Any])
        let installBody = try XCTUnwrap(installInput["body"] as? [String: Any])
        let installFrame = try XCTUnwrap(installBody["frame"] as? [String: Any])
        var grant = try XCTUnwrap(installFrame["grant"] as? [String: Any])
        grant["unexpected"] = true
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                RelayV2Grant.self,
                from: JSONSerialization.data(withJSONObject: grant)
            )
        )

        let endpoints = try XCTUnwrap(vectors["endpointTypes"] as? [[String: Any]])
        let invite = try XCTUnwrap(
            endpoints.first { ($0["wireType"] as? String) == "PairInviteV1" }
        )
        var inviteValue = try XCTUnwrap(invite["value"] as? [String: Any])
        var cert = try XCTUnwrap(inviteValue["dataSignCert"] as? [String: Any])
        cert["unexpected"] = true
        inviteValue["dataSignCert"] = cert
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                RelayPairInviteV1.self,
                from: JSONSerialization.data(withJSONObject: inviteValue)
            )
        )
    }

    func testEncodeEndpointRevalidatesVersionsLengthsAndNestedObjects() throws {
        let vectors = try loadRelayVectors()
        let endpoints = try XCTUnwrap(vectors["endpointTypes"] as? [[String: Any]])
        let inviteVector = try XCTUnwrap(
            endpoints.first { ($0["wireType"] as? String) == "PairInviteV1" }
        )
        let inviteData = try JSONSerialization.data(
            withJSONObject: XCTUnwrap(inviteVector["value"])
        )
        let decoded = try RelayV2JSONCodec.decodeEndpoint(.pairInvite, from: inviteData)
        guard case var .pairInvite(invite) = decoded else {
            return XCTFail("expected PairInviteV1")
        }

        invite.formatVersion = 2
        XCTAssertThrowsError(try RelayV2JSONCodec.encodeEndpoint(.pairInvite(invite)))

        invite = try pairInvite(from: inviteData)
        invite.relayProtocolVersion = 1
        XCTAssertThrowsError(try RelayV2JSONCodec.encodeEndpoint(.pairInvite(invite)))

        invite = try pairInvite(from: inviteData)
        invite.pairRoute = Data(repeating: 0, count: 15)
        XCTAssertThrowsError(try RelayV2JSONCodec.encodeEndpoint(.pairInvite(invite)))

        invite = try pairInvite(from: inviteData)
        invite.dataSignCert.subjectPubkey = Data(repeating: 0, count: 31)
        XCTAssertThrowsError(try RelayV2JSONCodec.encodeEndpoint(.pairInvite(invite)))
    }

    func testJSONAndBinaryEncodersRejectOversizeBeforeWireCompletion() throws {
        let oversizeJSON = Data(repeating: 0x20, count: RelayWireCodecV2.maxFrameBytes + 1)
        XCTAssertThrowsError(try RelayV2JSONCodec.decodeFrame(oversizeJSON)) { error in
            XCTAssertEqual(error as? RelayWireCodecError, .oversize)
        }
        XCTAssertThrowsError(
            try RelayV2JSONCodec.decodeEndpoint(.pairInvite, from: oversizeJSON)
        ) { error in
            XCTAssertEqual(error as? RelayWireCodecError, .oversize)
        }

        let sealedVector = try XCTUnwrap(
            try loadCryptoVectors()["sealed_blob"] as? [String: Any]
        )
        let baseCiphertext = Data(hex: try XCTUnwrap(sealedVector["ciphertextHex"] as? String))
        let baseWire = Data(hex: try XCTUnwrap(sealedVector["wireHex"] as? String))
        let sealedFixedBytes = baseWire.count - baseCiphertext.count
        let publishFixedBytes = 5 + 2 + 2 + 16 + 16 + 8 + 4
        let maximumCiphertextBytes = RelayWireCodecV2.maxFrameBytes
            - publishFixedBytes
            - sealedFixedBytes

        let nearLimit = try signedSealedBlob(
            from: sealedVector,
            ciphertext: Data(repeating: 0xA5, count: maximumCiphertextBytes)
        )
        XCTAssertNoThrow(
            try RelayWireCodecV2.encode(
                RelayV2OutboundFrame.publish(
                    streamRoute: Data(repeating: 0x33, count: 16),
                    generation: Data(repeating: 0x66, count: 16),
                    streamSeq: 7,
                    sealedBlob: nearLimit
                )
            )
        )

        let oversize = try signedSealedBlob(
            from: sealedVector,
            ciphertext: Data(repeating: 0xA5, count: maximumCiphertextBytes + 1)
        )
        XCTAssertThrowsError(
            try RelayWireCodecV2.encode(
                RelayV2OutboundFrame.publish(
                    streamRoute: Data(repeating: 0x33, count: 16),
                    generation: Data(repeating: 0x66, count: 16),
                    streamSeq: 7,
                    sealedBlob: oversize
                )
            )
        ) { error in
            XCTAssertEqual(error as? RelayWireCodecError, .oversize)
        }
    }

    func testSignedSealedFactoriesPreflightTheirExactOuterBudgets() throws {
        let sealedVector = try XCTUnwrap(
            try loadCryptoVectors()["sealed_blob"] as? [String: Any]
        )
        let baseCiphertext = Data(hex: try XCTUnwrap(sealedVector["ciphertextHex"] as? String))
        let baseWire = Data(hex: try XCTUnwrap(sealedVector["wireHex"] as? String))
        let sealedFixedBytes = baseWire.count - baseCiphertext.count
        let route = Data(repeating: 0x33, count: 16)
        let generation = Data(repeating: 0x66, count: 16)

        let cases: [(
            name: String,
            outerBytes: Int,
            make: (SignedSealedBlobV1) throws -> RelayV2OutboundFrame
        )] = [
            (
                "publish",
                5 + 2 + 2 + 16 + 16 + 8 + 4,
                { blob in
                    try RelayV2OutboundFrame.publish(
                        streamRoute: route,
                        generation: generation,
                        streamSeq: 7,
                        sealedBlob: blob
                    )
                }
            ),
            (
                "send",
                5 + 2 + 2 + 16 + 16 + 4,
                { blob in
                    try RelayV2OutboundFrame.send(
                        deviceRoute: route,
                        requestRoute: generation,
                        sealedBlob: blob
                    )
                }
            ),
            (
                "reply",
                5 + 2 + 2 + 16 + 16 + 4,
                { blob in
                    try RelayV2OutboundFrame.reply(
                        deviceRoute: route,
                        requestRoute: generation,
                        sealedBlob: blob
                    )
                }
            ),
        ]

        for boundary in cases {
            let maximumCiphertextBytes = RelayWireCodecV2.maxFrameBytes
                - boundary.outerBytes
                - sealedFixedBytes
            let nearLimit = try signedSealedBlob(
                from: sealedVector,
                ciphertext: Data(repeating: 0xA5, count: maximumCiphertextBytes)
            )
            XCTAssertNoThrow(try boundary.make(nearLimit), boundary.name)

            let oversize = try signedSealedBlob(
                from: sealedVector,
                ciphertext: Data(repeating: 0xA5, count: maximumCiphertextBytes + 1)
            )
            XCTAssertThrowsError(try boundary.make(oversize), boundary.name) { error in
                XCTAssertEqual(error as? RelayWireCodecError, .oversize, boundary.name)
            }
        }
    }

    func testErrorStringsRespectExactUTF8NearLimitAndOversizeBudgets() throws {
        let nilOptionalFixedBytes = 5 + 2 + 2 + 4 + 4 + 1
        let maximumCodeBytes = RelayWireCodecV2.maxFrameBytes - nilOptionalFixedBytes
        let nearCode = string(withUTF8Count: maximumCodeBytes)
        XCTAssertEqual(nearCode.utf8.count, maximumCodeBytes)
        let nearFrame = RelayV2OutboundFrame.control(
            .error(RelayV2Failure(code: nearCode, message: "", inReplyTo: nil))
        )
        XCTAssertEqual(try RelayWireCodecV2.encode(nearFrame).count, RelayWireCodecV2.maxFrameBytes)

        let oversizeCode = string(withUTF8Count: maximumCodeBytes + 1)
        let oversizeFrame = RelayV2OutboundFrame.control(
            .error(RelayV2Failure(code: oversizeCode, message: "", inReplyTo: nil))
        )
        XCTAssertThrowsError(try RelayWireCodecV2.encode(oversizeFrame)) { error in
            XCTAssertEqual(error as? RelayWireCodecError, .oversize)
        }

        let optionalFixedBytes = 5 + 2 + 2 + 4 + 4 + 1 + 4
        let maximumOptionalBytes = RelayWireCodecV2.maxFrameBytes - optionalFixedBytes
        let nearOptional = string(withUTF8Count: maximumOptionalBytes)
        let nearOptionalFrame = RelayV2OutboundFrame.control(
            .error(RelayV2Failure(code: "", message: "", inReplyTo: nearOptional))
        )
        XCTAssertEqual(
            try RelayWireCodecV2.encode(nearOptionalFrame).count,
            RelayWireCodecV2.maxFrameBytes
        )

        let oversizeOptionalFrame = RelayV2OutboundFrame.control(
            .error(
                RelayV2Failure(
                    code: "",
                    message: "",
                    inReplyTo: string(withUTF8Count: maximumOptionalBytes + 1)
                )
            )
        )
        XCTAssertThrowsError(try RelayWireCodecV2.encode(oversizeOptionalFrame)) { error in
            XCTAssertEqual(error as? RelayWireCodecError, .oversize)
        }
    }

    func testRawFrameBinaryEncodeIsNotPublicAPI() throws {
        let source = try String(contentsOf: relayV2TypesURL, encoding: .utf8)
        XCTAssertFalse(source.contains("public static func encode(_ frame: RelayV2Frame)"))
    }

    func testEveryEndpointVariantDecodesStrictlyAndReencodesSemantically() throws {
        let vectors = try loadRelayVectors()
        let endpoints = try XCTUnwrap(vectors["endpointTypes"] as? [[String: Any]])
        XCTAssertEqual(endpoints.count, 8)
        XCTAssertEqual(
            Set(endpoints.compactMap { $0["wireType"] as? String }),
            [
                "PairInviteV1", "PairRequestV1", "PairResponseV1",
                "DeviceAuthorizationV1", "KeyDirectoryV1", "KeyUpdateV1",
                "EpochBarrierV1", "SealedPayloadV1",
            ]
        )

        for vector in endpoints {
            let wireType = try XCTUnwrap(
                RelayEndpointWireType(rawValue: XCTUnwrap(vector["wireType"] as? String))
            )
            let input = try JSONSerialization.data(
                withJSONObject: XCTUnwrap(vector["value"])
            )
            let payload = try RelayV2JSONCodec.decodeEndpoint(wireType, from: input)
            XCTAssertEqual(
                try normalizedJSON(RelayV2JSONCodec.encodeEndpoint(payload)),
                try normalizedJSON(input),
                "Rust/Swift endpoint JSON drift for \(wireType.rawValue)"
            )
        }
    }

    func testRealJSONDecodeEntriesRejectUnknownFields() throws {
        let vectors = try loadRelayVectors()
        let outer = try XCTUnwrap(vectors["outerFrames"] as? [[String: Any]])
        let hello = try XCTUnwrap(outer.first { ($0["case"] as? String) == "hello" })
        var helloInput = try XCTUnwrap(hello["input"] as? [String: Any])
        helloInput["unexpected"] = true
        XCTAssertThrowsError(
            try RelayV2JSONCodec.decodeFrame(
                try JSONSerialization.data(withJSONObject: helloInput)
            )
        )

        var nestedInput = try XCTUnwrap(hello["input"] as? [String: Any])
        var body = try XCTUnwrap(nestedInput["body"] as? [String: Any])
        var frame = try XCTUnwrap(body["frame"] as? [String: Any])
        frame["unexpected"] = true
        body["frame"] = frame
        nestedInput["body"] = body
        XCTAssertThrowsError(
            try RelayV2JSONCodec.decodeFrame(
                try JSONSerialization.data(withJSONObject: nestedInput)
            )
        )

        let endpoints = try XCTUnwrap(vectors["endpointTypes"] as? [[String: Any]])
        let invite = try XCTUnwrap(
            endpoints.first { ($0["wireType"] as? String) == "PairInviteV1" }
        )
        var inviteValue = try XCTUnwrap(invite["value"] as? [String: Any])
        inviteValue["unexpected"] = true
        XCTAssertThrowsError(
            try RelayV2JSONCodec.decodeEndpoint(
                .pairInvite,
                from: try JSONSerialization.data(withJSONObject: inviteValue)
            )
        )

        var nestedInvite = try XCTUnwrap(invite["value"] as? [String: Any])
        var cert = try XCTUnwrap(nestedInvite["dataSignCert"] as? [String: Any])
        cert["unexpected"] = true
        nestedInvite["dataSignCert"] = cert
        XCTAssertThrowsError(
            try RelayV2JSONCodec.decodeEndpoint(
                .pairInvite,
                from: try JSONSerialization.data(withJSONObject: nestedInvite)
            )
        )
    }

    func testBinaryDecodeFailsClosedForMalformedFrames() throws {
        let vectors = try loadRelayVectors()
        let outer = try XCTUnwrap(vectors["outerFrames"] as? [[String: Any]])
        let hello = try XCTUnwrap(outer.first { ($0["case"] as? String) == "hello" })
        let good = Data(hex: try XCTUnwrap(hello["expectedHex"] as? String))

        var badMagic = good
        badMagic[badMagic.startIndex] = 0
        XCTAssertThrowsError(try RelayWireCodecV2.decode(badMagic))

        var trailing = good
        trailing.append(0)
        XCTAssertThrowsError(try RelayWireCodecV2.decode(trailing))

        var unknownKind = good
        unknownKind[7] = 0xFF
        unknownKind[8] = 0xFF
        XCTAssertThrowsError(try RelayWireCodecV2.decode(unknownKind))

        XCTAssertThrowsError(
            try RelayWireCodecV2.decode(Data(repeating: 0, count: 4 * 1024 * 1024 + 1))
        )
    }

    func testEndpointHeaderReusesP16CanonicalAADAndTBSFacts() throws {
        let relayVectors = try loadRelayVectors()
        let endpoints = try XCTUnwrap(relayVectors["endpointTypes"] as? [[String: Any]])
        let sealed = try XCTUnwrap(
            endpoints.first { ($0["wireType"] as? String) == "SealedPayloadV1" }
        )
        let sealedInput = try JSONSerialization.data(
            withJSONObject: XCTUnwrap(sealed["value"])
        )
        let endpoint = try RelayV2JSONCodec.decodeEndpoint(.sealedPayload, from: sealedInput)
        guard case let .sealedPayload(header) = endpoint else {
            return XCTFail("expected SealedPayloadV1 endpoint header")
        }
        XCTAssertEqual(header.payloadKind, .conversationEvent)

        let cryptoVectors = try loadCryptoVectors()
        let outerContext = OuterContextV1(
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
        let aad = try CanonicalCodec.encodeAAD(outerContext)
        let aadVector = try XCTUnwrap(cryptoVectors["outer_context_aad"] as? [String: Any])
        XCTAssertEqual(aad, Data(hex: try XCTUnwrap(aadVector["aadHex"] as? String)))

        let sealedVector = try XCTUnwrap(cryptoVectors["sealed_blob"] as? [String: Any])
        let unsigned = UnsignedSealedBlobV1(
            formatVersion: header.formatVersion,
            payloadKind: header.payloadKind,
            keyID: KeyIDV1(purpose: .conversationDEK, epoch: 4),
            keyEpoch: 4,
            keyDirectoryRevision: 2,
            nonce: Data(hex: try XCTUnwrap(sealedVector["nonceHex"] as? String)),
            ciphertext: Data(hex: try XCTUnwrap(sealedVector["ciphertextHex"] as? String))
        )
        XCTAssertEqual(
            try CanonicalCodec.sealedBlobTBS(unsigned, context: outerContext),
            Data(hex: try XCTUnwrap(sealedVector["tbsHex"] as? String))
        )
    }

    private func loadRelayVectors() throws -> [String: Any] {
        let url = repoRoot
            .appendingPathComponent("protocol")
            .appendingPathComponent("agentdeck")
            .appendingPathComponent("fixtures")
            .appendingPathComponent("relay-v2-wire-vectors.json")
        return try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        )
    }

    private func loadCryptoVectors() throws -> [String: Any] {
        let url = repoRoot
            .appendingPathComponent("protocol")
            .appendingPathComponent("agentdeck")
            .appendingPathComponent("crypto-vectors-v1.json")
        return try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        )
    }

    private func normalizedJSON(_ data: Data) throws -> Data {
        let object = try JSONSerialization.jsonObject(with: data)
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private func signedSealedBlob(
        from vector: [String: Any],
        ciphertext: Data? = nil
    ) throws -> SignedSealedBlobV1 {
        let resolvedCiphertext = try ciphertext
            ?? Data(hex: XCTUnwrap(vector["ciphertextHex"] as? String))
        return SignedSealedBlobV1(
            inner: UnsignedSealedBlobV1(
                formatVersion: 1,
                payloadKind: .conversationEvent,
                keyID: KeyIDV1(purpose: .conversationDEK, epoch: 4),
                keyEpoch: 4,
                keyDirectoryRevision: 2,
                nonce: Data(hex: try XCTUnwrap(vector["nonceHex"] as? String)),
                ciphertext: resolvedCiphertext
            ),
            signature: Data(hex: try XCTUnwrap(vector["signatureHex"] as? String))
        )
    }

    private func pairInvite(from data: Data) throws -> RelayPairInviteV1 {
        guard case let .pairInvite(value) = try RelayV2JSONCodec.decodeEndpoint(
            .pairInvite,
            from: data
        ) else {
            throw RelayWireCodecError.unknownField("PairInviteV1")
        }
        return value
    }

    private func lengthPrefixedPayload(in data: Data, after offset: Int) throws -> Data {
        guard offset >= 0, offset + 4 <= data.count else {
            throw RelayWireCodecError.shortInput
        }
        let length = data[offset..<(offset + 4)].reduce(UInt32(0)) {
            ($0 << 8) | UInt32($1)
        }
        let start = offset + 4
        let end = start + Int(length)
        guard end <= data.count else {
            throw RelayWireCodecError.lengthOutOfBounds
        }
        return data[start..<end]
    }

    private func string(withUTF8Count count: Int) -> String {
        String(repeating: "界", count: count / 3) + String(repeating: "x", count: count % 3)
    }

    private var repoRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private var relayV2TypesURL: URL {
        repoRoot.appendingPathComponent("Sources/AgentDeckRelayClient/Wire/RelayV2Types.swift")
    }
}

private extension Data {
    init(hex: String) {
        self.init()
        reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
    }
}
