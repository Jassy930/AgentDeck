import Foundation
import XCTest
@testable import AgentDeckRelayClient

final class RelayV2WireVerticalSliceTests: XCTestCase {
    func testHelloMatchesRustExpectedHexAndRoundTrips() throws {
        let input = Data(
            #"{"version":2,"body":{"frameKind":"hello","frame":{"protocolVersion":2}}}"#.utf8
        )
        let frame = try RelayV2JSONCodec.decodeFrame(input)
        let encoded = try RelayWireCodecV2.encode(frame)
        XCTAssertEqual(encoded, Data(hex: "4144525632000200000002"))
        XCTAssertEqual(try RelayWireCodecV2.decode(encoded), frame)
    }

    func testImplementedFamiliesMatchRustVectors() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("protocol/agentdeck/fixtures/relay-v2-wire-vectors.json")
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        )
        let all = try XCTUnwrap(root["outerFrames"] as? [[String: Any]])
        let implementedFamilies: Set<String> = [
            "handshake", "pairing", "stream", "request", "authControl", "runtime",
        ]
        let vectors = all.filter {
            implementedFamilies.contains(($0["family"] as? String) ?? "")
        }
        XCTAssertEqual(vectors.count, 28)
        for vector in vectors {
            let name = try XCTUnwrap(vector["case"] as? String)
            let input = try JSONSerialization.data(withJSONObject: XCTUnwrap(vector["input"]))
            let frame = try RelayV2JSONCodec.decodeFrame(input)
            let encoded = try RelayWireCodecV2.encode(frame)
            XCTAssertEqual(
                encoded,
                Data(hex: try XCTUnwrap(vector["expectedHex"] as? String)),
                name
            )
            XCTAssertEqual(try RelayWireCodecV2.decode(encoded), frame)
        }
    }
}

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
            let encoded = try RelayWireCodecV2.encode(frame)
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

    private var repoRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
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
