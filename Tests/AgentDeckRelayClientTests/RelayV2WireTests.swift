import Foundation
import XCTest
@testable import AgentDeckRelayClient

final class RelayV2WireTests: XCTestCase {
    func testEveryRustOuterVectorMatchesBinaryCodecAndRoundTrips() throws {
        let vectors = try loadRelayVectors()
        let outer = try XCTUnwrap(vectors["outerFrames"] as? [[String: Any]])
        XCTAssertEqual(outer.count, 30)
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

    func testPairingHelloMirrorsKind29StrictJSONAndTypedOutbound() throws {
        let outer = try XCTUnwrap(
            try loadRelayVectors()["outerFrames"] as? [[String: Any]]
        )
        let vector = try XCTUnwrap(
            outer.first { ($0["case"] as? String) == "pairingHello" }
        )
        let input = try XCTUnwrap(vector["input"] as? [String: Any])
        let inputData = try JSONSerialization.data(withJSONObject: input)
        let expected = Data(hex: try XCTUnwrap(vector["expectedHex"] as? String))
        let relayServerID = Data(repeating: 0x88, count: 16)
        let pairRoute = Data(repeating: 0x55, count: 16)

        let decoded = try RelayV2JSONCodec.decodeFrame(inputData)
        guard case let .pairingHello(serverID, route) = decoded.body else {
            return XCTFail("expected PairingHello")
        }
        XCTAssertEqual(serverID, relayServerID)
        XCTAssertEqual(route, pairRoute)
        XCTAssertEqual(try RelayWireCodecV2.encodeFixture(decoded), expected)
        XCTAssertEqual(try RelayWireCodecV2.decode(expected), decoded)
        XCTAssertEqual(expected[7], 0)
        XCTAssertEqual(expected[8], 29)

        XCTAssertEqual(
            try RelayWireCodecV2.encode(
                .control(
                    .pairingHello(
                        relayServerId: relayServerID,
                        pairRoute: pairRoute
                    )
                )
            ),
            expected
        )

        var unknownInput = input
        var body = try XCTUnwrap(unknownInput["body"] as? [String: Any])
        var frame = try XCTUnwrap(body["frame"] as? [String: Any])
        frame["unexpected"] = true
        body["frame"] = frame
        unknownInput["body"] = body
        let unknownData = try JSONSerialization.data(withJSONObject: unknownInput)
        XCTAssertThrowsError(try RelayV2JSONCodec.decodeFrame(unknownData))
        XCTAssertThrowsError(try JSONDecoder().decode(RelayV2Frame.self, from: unknownData))
    }

    func testRetirementControlFramesMirrorFrozenRustKindsAndPayloads() throws {
        let outer = try XCTUnwrap(
            try loadRelayVectors()["outerFrames"] as? [[String: Any]]
        )
        let machineRoute = Data(repeating: 0x11, count: 16)
        let rootKeyID = Data(repeating: 0x77, count: 16)
        let signature = Data(repeating: 0xB0, count: 64)

        let retireVector = try XCTUnwrap(
            outer.first { ($0["case"] as? String) == "retireMachine" }
        )
        let retireInput = try JSONSerialization.data(
            withJSONObject: XCTUnwrap(retireVector["input"])
        )
        let retireFrame = try RelayV2JSONCodec.decodeFrame(retireInput)
        guard case let .retireMachine(route, root, epoch, signed) = retireFrame.body else {
            return XCTFail("expected RetireMachine")
        }
        XCTAssertEqual(route, machineRoute)
        XCTAssertEqual(root, rootKeyID)
        XCTAssertEqual(epoch, 4)
        XCTAssertEqual(signed, signature)
        XCTAssertEqual(
            try RelayWireCodecV2.encode(
                .control(
                    .retireMachine(
                        machineRoute: machineRoute,
                        rootKeyId: rootKeyID,
                        trustEpoch: 4,
                        signature: signature
                    )
                )
            ),
            Data(hex: try XCTUnwrap(retireVector["expectedHex"] as? String))
        )

        let committedVector = try XCTUnwrap(
            outer.first { ($0["case"] as? String) == "retirementCommitted" }
        )
        let committedInput = try JSONSerialization.data(
            withJSONObject: XCTUnwrap(committedVector["input"])
        )
        let committedFrame = try RelayV2JSONCodec.decodeFrame(committedInput)
        let retireHash = Data(
            hex: "251660b89c346510f961d588109a333495af462064cb7557b35ed2ebecb5e9a4"
        )
        guard case let .retirementCommitted(route, epoch, hash) = committedFrame.body else {
            return XCTFail("expected RetirementCommitted")
        }
        XCTAssertEqual(route, machineRoute)
        XCTAssertEqual(epoch, 4)
        XCTAssertEqual(hash, retireHash)

        let committedWire = try RelayWireCodecV2.encode(
            .control(
                .retirementCommitted(
                    machineRoute: machineRoute,
                    trustEpoch: 4,
                    retireHash: retireHash
                )
            )
        )
        XCTAssertEqual(committedWire[7], 0)
        XCTAssertEqual(committedWire[8], 28)
        XCTAssertEqual(
            committedWire,
            Data(hex: try XCTUnwrap(committedVector["expectedHex"] as? String))
        )
    }

    func testRetirementJSONPayloadsAreStrictAndRootKeyIsRequired() throws {
        let outer = try XCTUnwrap(
            try loadRelayVectors()["outerFrames"] as? [[String: Any]]
        )
        let retireVector = try XCTUnwrap(
            outer.first { ($0["case"] as? String) == "retireMachine" }
        )
        var retireInput = try XCTUnwrap(retireVector["input"] as? [String: Any])
        var retireBody = try XCTUnwrap(retireInput["body"] as? [String: Any])
        var retirePayload = try XCTUnwrap(retireBody["frame"] as? [String: Any])
        retirePayload["unexpected"] = true
        retireBody["frame"] = retirePayload
        retireInput["body"] = retireBody
        XCTAssertThrowsError(
            try RelayV2JSONCodec.decodeFrame(
                try JSONSerialization.data(withJSONObject: retireInput)
            )
        )

        retireInput = try XCTUnwrap(retireVector["input"] as? [String: Any])
        retireBody = try XCTUnwrap(retireInput["body"] as? [String: Any])
        retirePayload = try XCTUnwrap(retireBody["frame"] as? [String: Any])
        retirePayload.removeValue(forKey: "rootKeyId")
        retireBody["frame"] = retirePayload
        retireInput["body"] = retireBody
        XCTAssertThrowsError(
            try RelayV2JSONCodec.decodeFrame(
                try JSONSerialization.data(withJSONObject: retireInput)
            )
        )

        let committedVector = try XCTUnwrap(
            outer.first { ($0["case"] as? String) == "retirementCommitted" }
        )
        var committedInput = try XCTUnwrap(committedVector["input"] as? [String: Any])
        var committedBody = try XCTUnwrap(committedInput["body"] as? [String: Any])
        var committedPayload = try XCTUnwrap(committedBody["frame"] as? [String: Any])
        committedPayload["signedRetirement"] = ["opaque": true]
        committedBody["frame"] = committedPayload
        committedInput["body"] = committedBody
        XCTAssertThrowsError(
            try RelayV2JSONCodec.decodeFrame(
                try JSONSerialization.data(withJSONObject: committedInput)
            )
        )
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
        XCTAssertEqual(endpoints.count, 12)
        XCTAssertEqual(
            Set(endpoints.compactMap { $0["wireType"] as? String }),
            [
                "PairInviteV1", "PairRequestV1", "PairResponseV1",
                "PairPendingV1", "PairingControlEnvelopeV1", "PairResponseReceivedV1",
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

    func testPairingEndpointTamperingFailsClosed() throws {
        let endpoints = try XCTUnwrap(
            try loadRelayVectors()["endpointTypes"] as? [[String: Any]]
        )

        var pending = try endpointValue("PairPendingV1", in: endpoints)
        pending["requestHash"] = Data(repeating: 0x31, count: 31).base64EncodedString()
        assertEndpointDecodeRejected(.pairPending, value: pending)

        pending = try endpointValue("PairPendingV1", in: endpoints)
        pending["requestHash"] = Data(repeating: 0, count: 32).base64EncodedString()
        assertEndpointDecodeRejected(.pairPending, value: pending)

        var request = try endpointValue("PairRequestV1", in: endpoints)
        request["enc"] = Data(repeating: 0x07, count: 31).base64EncodedString()
        assertEndpointDecodeRejected(.pairRequest, value: request)

        request = try endpointValue("PairRequestV1", in: endpoints)
        request["ciphertext"] = Data().base64EncodedString()
        assertEndpointDecodeRejected(.pairRequest, value: request)

        request = try endpointValue("PairRequestV1", in: endpoints)
        request["ciphertext"] = Data(repeating: 0x09, count: 256 * 1024 + 1)
            .base64EncodedString()
        assertEndpointDecodeRejected(.pairRequest, value: request)

        request = try endpointValue("PairRequestV1", in: endpoints)
        request["deviceProofSignature"] = Data(repeating: 0, count: 64)
            .base64EncodedString()
        assertEndpointDecodeRejected(.pairRequest, value: request)

        var response = try endpointValue("PairResponseV1", in: endpoints)
        response.removeValue(forKey: "info")
        assertEndpointDecodeRejected(.pairResponse, value: response)

        response = try endpointValue("PairResponseV1", in: endpoints)
        var responseInfo = try XCTUnwrap(response["info"] as? [String: Any])
        responseInfo["deviceRoute"] = Data(repeating: 0x44, count: 15).base64EncodedString()
        response["info"] = responseInfo
        assertEndpointDecodeRejected(.pairResponse, value: response)

        response = try endpointValue("PairResponseV1", in: endpoints)
        responseInfo = try XCTUnwrap(response["info"] as? [String: Any])
        responseInfo["unexpected"] = true
        response["info"] = responseInfo
        assertEndpointDecodeRejected(.pairResponse, value: response)

        var receipt = try endpointValue("PairResponseReceivedV1", in: endpoints)
        receipt["grantHash"] = Data(repeating: 0, count: 32).base64EncodedString()
        assertEndpointDecodeRejected(.pairResponseReceived, value: receipt)

        receipt = try endpointValue("PairResponseReceivedV1", in: endpoints)
        receipt["signature"] = Data(repeating: 0xB0, count: 63).base64EncodedString()
        assertEndpointDecodeRejected(.pairResponseReceived, value: receipt)
    }

    func testPairDataCarriesOnlyRelayVisiblePairingEnvelopes() throws {
        let endpoints = try XCTUnwrap(
            try loadRelayVectors()["endpointTypes"] as? [[String: Any]]
        )
        let pairRoute = Data(repeating: 0x55, count: 16)

        for wireType in [
            RelayEndpointWireType.pairRequest,
            .pairingControlEnvelope,
            .pairResponse,
        ] {
            let value = try endpointValue(wireType.rawValue, in: endpoints)
            let payload = try RelayV2JSONCodec.decodeEndpoint(
                wireType,
                from: JSONSerialization.data(withJSONObject: value)
            )
            XCTAssertNoThrow(
                try RelayV2OutboundFrame.pairData(
                    pairRoute: pairRoute,
                    payload: payload
                ),
                wireType.rawValue
            )
        }

        for wireType in [
            RelayEndpointWireType.pairPending,
            .pairResponseReceived,
            .deviceAuthorization,
        ] {
            let value = try endpointValue(wireType.rawValue, in: endpoints)
            let payload = try RelayV2JSONCodec.decodeEndpoint(
                wireType,
                from: JSONSerialization.data(withJSONObject: value)
            )
            XCTAssertThrowsError(
                try RelayV2OutboundFrame.pairData(
                    pairRoute: pairRoute,
                    payload: payload
                ),
                wireType.rawValue
            )
        }
    }

    func testDeviceAuthorizationRequiresCanonicalBoundedAuthorizationSets() throws {
        let endpoints = try XCTUnwrap(
            try loadRelayVectors()["endpointTypes"] as? [[String: Any]]
        )
        let baseline = try endpointValue("DeviceAuthorizationV1", in: endpoints)

        var unordered = baseline
        unordered["capabilities"] = ["approval", "catalog"]
        unordered["permissions"] = ["catalogRead", "approvalResolve"]
        assertEndpointDecodeRejected(.deviceAuthorization, value: unordered)

        var duplicate = baseline
        duplicate["capabilities"] = ["approval", "approval"]
        assertEndpointDecodeRejected(.deviceAuthorization, value: duplicate)

        var permissionWithoutCapability = baseline
        permissionWithoutCapability["permissions"] = ["promptSend"]
        assertEndpointDecodeRejected(
            .deviceAuthorization,
            value: permissionWithoutCapability
        )
    }

    func testPairInviteRequiresCanonicalRootWSSOrigin() throws {
        let endpoints = try XCTUnwrap(
            try loadRelayVectors()["endpointTypes"] as? [[String: Any]]
        )
        let baseline = try endpointValue("PairInviteV1", in: endpoints)

        for invalidURL in [
            "wss://relay.example.test/path",
            "wss://user@relay.example.test/",
            "wss://relay.example.test:0/",
            "wss://relay.example.test/?query=1",
            "wss://relay.example.test/#fragment",
        ] {
            var invite = baseline
            invite["wssUrl"] = invalidURL
            assertEndpointDecodeRejected(
                .pairInvite,
                value: invite,
                message: invalidURL
            )
        }
        var zeroCertExpiry = baseline
        var certificate = try XCTUnwrap(zeroCertExpiry["dataSignCert"] as? [String: Any])
        certificate["notAfterMs"] = 0
        zeroCertExpiry["dataSignCert"] = certificate
        assertEndpointDecodeRejected(.pairInvite, value: zeroCertExpiry)
    }

    func testEpochBarrierInnerCursorAndTransferPartKindMirrorRust() throws {
        let endpoints = try XCTUnwrap(
            try loadRelayVectors()["endpointTypes"] as? [[String: Any]]
        )
        let barrierVector = try XCTUnwrap(
            endpoints.first { ($0["case"] as? String) == "epochBarrier" }
        )
        let barrierData = try JSONSerialization.data(
            withJSONObject: XCTUnwrap(barrierVector["value"])
        )
        guard case let .epochBarrier(barrier) = try RelayV2JSONCodec.decodeEndpoint(
            .epochBarrier,
            from: barrierData
        ),
            case let .conversation(conversationID, .at(cursor)) = barrier.innerCursor
        else {
            return XCTFail("EpochBarrier must carry a tagged conversation inner cursor")
        }
        XCTAssertEqual(conversationID, "conversation-epoch-barrier")
        XCTAssertEqual(cursor, 41)

        let transferVector = try XCTUnwrap(
            endpoints.first { ($0["case"] as? String) == "sealedPayloadTransferPart" }
        )
        let transferData = try JSONSerialization.data(
            withJSONObject: XCTUnwrap(transferVector["value"])
        )
        guard case let .sealedPayload(payload) = try RelayV2JSONCodec.decodeEndpoint(
            .sealedPayload,
            from: transferData
        ) else {
            return XCTFail("expected sealed payload endpoint")
        }
        XCTAssertEqual(payload.payloadKind, .transferPart)
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

    private func endpointValue(
        _ wireType: String,
        in endpoints: [[String: Any]]
    ) throws -> [String: Any] {
        let vector = try XCTUnwrap(
            endpoints.first { ($0["wireType"] as? String) == wireType }
        )
        return try XCTUnwrap(vector["value"] as? [String: Any])
    }

    private func assertEndpointDecodeRejected(
        _ wireType: RelayEndpointWireType,
        value: [String: Any],
        message: String = "",
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try RelayV2JSONCodec.decodeEndpoint(
                wireType,
                from: JSONSerialization.data(withJSONObject: value)
            ),
            message,
            file: file,
            line: line
        )
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
