import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class DeviceCryptoStateTests: XCTestCase {
  func testCompleteTypedStateRoundTripsAndReencodesExactly() throws {
    let original = try makeState()

    let encoded = try DeviceCryptoStateCodec.encode(original)
    let decoded = try DeviceCryptoStateCodec.decode(encoded)
    let snapshot = try CryptoStateSnapshot(original)
    let reopened = try CryptoStateSnapshot(authenticatedCanonicalBytes: encoded)

    XCTAssertEqual(decoded, original)
    XCTAssertEqual(try DeviceCryptoStateCodec.encode(decoded), encoded)
    XCTAssertEqual(snapshot.canonicalBytes, encoded)
    XCTAssertEqual(reopened.state, original)
    XCTAssertEqual(reopened.canonicalBytes, encoded)
    XCTAssertEqual(reopened.commitment, snapshot.commitment)
    XCTAssertEqual(encoded.prefix(4), Data("ADDS".utf8))
    XCTAssertEqual(decoded.replayStates.map(\.status), original.replayStates.map(\.status))
    XCTAssertEqual(
      decoded.streamStates.map(\.outerCursor), original.streamStates.map(\.outerCursor))
    XCTAssertEqual(
      decoded.streamStates.map(\.innerCursor), original.streamStates.map(\.innerCursor))
  }

  func testCanonicalEncoderEnforcesBudgetBeforeReturningOversizedBytes() throws {
    let state = try makeState()
    let encoded = try DeviceCryptoStateCodec.encode(state)

    XCTAssertEqual(
      try DeviceCryptoStateCodec.encode(state, maximumDataBytes: encoded.count),
      encoded
    )
    XCTAssertThrowsError(
      try DeviceCryptoStateCodec.encode(state, maximumDataBytes: encoded.count - 1)
    ) { error in
      XCTAssertEqual(error as? DeviceCryptoStateError, .inputTooLarge)
    }
    XCTAssertThrowsError(
      try DeviceCryptoStateCodec.encode(state, maximumDataBytes: 11)
    ) { error in
      XCTAssertEqual(error as? DeviceCryptoStateError, .inputTooLarge)
    }
  }

  func testStatePublicSurfaceIsClosedTypedAndTranscriptFree() throws {
    let state = try makeState()
    let snapshot = try CryptoStateSnapshot(state)
    let propertyNames = Mirror(reflecting: state).children.compactMap(\.label)

    XCTAssertEqual(
      propertyNames,
      [
        "stateRevision",
        "trustScope",
        "keyDirectory",
        "senderCounter",
        "securityState",
        "replayStates",
        "streamStates",
      ])
    XCTAssertFalse(propertyNames.contains("data"))
    XCTAssertFalse(propertyNames.contains("snapshot"))
    XCTAssertFalse(propertyNames.contains("prompt"))
    XCTAssertFalse(propertyNames.contains("output"))
    XCTAssertFalse(propertyNames.contains("transcript"))
    XCTAssertEqual(state.debugDescription, "DeviceCryptoStateV1(revision: 41, <redacted>)")
    XCTAssertEqual(snapshot.state, state)
    XCTAssertEqual(snapshot.commitment.count, 32)
    XCTAssertEqual(snapshot.debugDescription, "CryptoStateSnapshot(v1, revision: 41, <redacted>)")

    let repositoryRoot = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let sourceURL = repositoryRoot.appendingPathComponent(
      "Sources/AgentDeckRelayClient/Storage/DeviceCryptoState.swift"
    )
    let source = try String(contentsOf: sourceURL, encoding: .utf8)
    let declarationStart = try XCTUnwrap(source.range(of: "public struct DeviceCryptoStateV1"))
    let declarationEnd = try XCTUnwrap(
      source.range(
        of: "public enum DeviceCryptoStateError",
        range: declarationStart.upperBound..<source.endIndex
      ))
    let publicSurface = String(source[declarationStart.lowerBound..<declarationEnd.lowerBound])
    let forbiddenPatterns = [
      #"public\s+(?:let|var)\s+(?:data|snapshot|prompt|output|transcript)\b"#,
      #"public\s+init\s*\(\s*(?:data|snapshot|prompt|output|transcript)\s*:"#,
    ]
    for pattern in forbiddenPatterns {
      let expression = try NSRegularExpression(pattern: pattern)
      let range = NSRange(publicSurface.startIndex..., in: publicSurface)
      XCTAssertNil(
        expression.firstMatch(in: publicSurface, range: range),
        "DeviceCryptoStateV1 不能暴露任意字节或 transcript 持久化入口"
      )
    }

    let storeSource = try String(
      contentsOf: repositoryRoot.appendingPathComponent(
        "Sources/AgentDeckRelayClient/Storage/CryptoStateStore.swift"
      ),
      encoding: .utf8
    )
    let snapshotStart = try XCTUnwrap(storeSource.range(of: "public struct CryptoStateSnapshot"))
    let snapshotEnd = try XCTUnwrap(
      storeSource.range(
        of: "public enum CryptoStateCommit",
        range: snapshotStart.upperBound..<storeSource.endIndex
      ))
    let snapshotSurface = String(storeSource[snapshotStart.lowerBound..<snapshotEnd.lowerBound])
    let forbiddenSnapshotPatterns = [
      #"public\s+(?:let|var)\s+(?:data|encoded|canonicalBytes|plaintext|prompt|output|transcript)\b"#,
      #"public\s+init\s*\([^\)]*(?:Data|data|bytes|plaintext|prompt|output|transcript)"#,
    ]
    for pattern in forbiddenSnapshotPatterns {
      let expression = try NSRegularExpression(pattern: pattern)
      let range = NSRange(snapshotSurface.startIndex..., in: snapshotSurface)
      XCTAssertNil(
        expression.firstMatch(in: snapshotSurface, range: range),
        "CryptoStateSnapshot 的 production API 只能接收 typed state"
      )
    }
  }

  func testTrustRoutesAndPinnedIdentifiersRejectWrongLengthOrAllZero() throws {
    let zero16 = Data(repeating: 0, count: 16)
    let zero32 = Data(repeating: 0, count: 32)

    assertStateError(.invalidTrustScope) {
      try makeTrust(relayServerID: Data(repeating: 1, count: 15))
    }
    assertStateError(.invalidTrustScope) {
      try makeTrust(relayServerID: zero16)
    }
    assertStateError(.invalidTrustScope) {
      try makeTrust(machineRootFingerprint: Data(repeating: 1, count: 31))
    }
    assertStateError(.invalidTrustScope) {
      try makeTrust(machineRootFingerprint: zero32)
    }
    assertStateError(.invalidTrustScope) {
      try makeTrust(machineRoute: Data(repeating: 1, count: 15))
    }
    assertStateError(.invalidTrustScope) {
      try makeTrust(machineRoute: zero16)
    }
    assertStateError(.invalidTrustScope) {
      try makeTrust(deviceRoute: Data(repeating: 1, count: 17))
    }
    assertStateError(.invalidTrustScope) {
      try makeTrust(deviceRoute: zero16)
    }
    assertStateError(.invalidTrustScope) {
      try makeTrust(grantSerial: 0)
    }
    assertStateError(.invalidTrustScope) {
      try makeTrust(trustEpoch: 0)
    }

    assertStateError(.invalidKeyDirectory) {
      try makeWrappedKey(deviceRoute: Data(repeating: 1, count: 15))
    }
    assertStateError(.invalidKeyDirectory) {
      try makeWrappedKey(deviceRoute: zero16)
    }
    assertStateError(.invalidKeyDirectory) {
      try makeWrappedKey(streamRoute: Data(repeating: 1, count: 15))
    }
    assertStateError(.invalidKeyDirectory) {
      try makeWrappedKey(streamRoute: zero16)
    }

    let entries = try defaultKeyEntries()
    assertStateError(.invalidKeyDirectory) {
      try DeviceKeyDirectoryV1(
        revision: Fixture.directoryRevision,
        entries: entries,
        signature: Data(repeating: 0x91, count: 63)
      )
    }
    assertStateError(.invalidKeyDirectory) {
      try DeviceKeyDirectoryV1(
        revision: Fixture.directoryRevision,
        entries: entries,
        signature: Data(repeating: 0, count: 64)
      )
    }

    assertStateError(.invalidCursor) {
      try makeStreamState(streamRoute: Data(repeating: 1, count: 15))
    }
    assertStateError(.invalidCursor) {
      try makeStreamState(streamRoute: zero16)
    }
    assertStateError(.invalidCursor) {
      try makeStreamState(generation: Data(repeating: 1, count: 15))
    }
    assertStateError(.invalidCursor) {
      try makeStreamState(generation: zero16)
    }
  }

  func testSenderPurposeEpochRevisionAndReservationConstraints() throws {
    for purpose in [KeyPurpose.catalog, .conversationDEK, .deviceReplyTx] {
      assertStateError(.invalidSenderCounter) {
        try makeSender(keyID: KeyIDV1(purpose: purpose, epoch: Fixture.senderEpoch))
      }
    }
    assertStateError(.invalidSenderCounter) {
      try makeSender(keyID: KeyIDV1(purpose: .deviceCommandTx, epoch: 0))
    }
    assertStateError(.invalidSenderCounter) {
      try makeSender(keyDirectoryRevision: 0)
    }
    assertStateError(.invalidSenderCounter) {
      try makeSender(noncePrefix: Data(repeating: 1, count: 3))
    }
    assertStateError(.invalidSenderCounter) {
      try makeSender(reservationID: Data(repeating: 1, count: 15))
    }
    assertStateError(.invalidSenderCounter) {
      try makeSender(reservedHighWater: 0, reservationID: Fixture.reservationID)
    }
    assertStateError(.invalidSenderCounter) {
      try makeSender(
        reservedHighWater: CounterBlock.size,
        reservationID: Data(repeating: 0, count: 16)
      )
    }

    XCTAssertNoThrow(
      try makeSender(
        reservedHighWater: 0,
        reservationID: Data(repeating: 0, count: 16)
      ))
    XCTAssertNoThrow(try makeSender())

    let directory = try makeDirectory()
    assertStateError(.invalidState) {
      try makeState(
        keyDirectory: directory,
        senderCounter: makeSender(keyDirectoryRevision: directory.revision + 1)
      )
    }
    assertStateError(.invalidState) {
      try makeState(
        keyDirectory: directory,
        senderCounter: makeSender(
          keyID: KeyIDV1(purpose: .deviceCommandTx, epoch: Fixture.senderEpoch + 100)
        )
      )
    }

    let wrongRouteDirectory = try makeDirectory(deviceRoute: tagged(0xE1, count: 16))
    assertStateError(.invalidState) {
      try makeState(keyDirectory: wrongRouteDirectory)
    }
  }

  func testKeyDirectoryRequiresExactV1ShapeCanonicalOrderAndRequiredSlots() throws {
    XCTAssertEqual(DeviceWrappedKeyV1.encapsulatedKeyBytes, 32)
    XCTAssertEqual(DeviceWrappedKeyV1.wrappedKeyBytes, 48)
    XCTAssertEqual(DeviceKeyDirectoryV1.maximumEntries, 1_027)

    assertStateError(.invalidKeyDirectory) {
      try makeWrappedKey(enc: tagged(0xA1, count: 31))
    }
    assertStateError(.invalidKeyDirectory) {
      try makeWrappedKey(enc: Data(repeating: 0, count: 32))
    }
    assertStateError(.invalidKeyDirectory) {
      try makeWrappedKey(wrappedKey: tagged(0xB1, count: 47))
    }
    assertStateError(.invalidKeyDirectory) {
      try makeWrappedKey(wrappedKey: Data(repeating: 0, count: 48))
    }
    assertStateError(.invalidKeyDirectory) {
      try makeWrappedKey(
        keyID: Fixture.conversationKeyID,
        streamRoute: nil
      )
    }
    assertStateError(.invalidKeyDirectory) {
      try makeWrappedKey(
        keyID: Fixture.catalogKeyID,
        streamRoute: Fixture.streamRouteA
      )
    }

    let valid = try defaultKeyEntries()
    XCTAssertNoThrow(
      try DeviceKeyDirectoryV1(
        revision: Fixture.directoryRevision,
        entries: valid,
        signature: Fixture.signature
      ))
    assertStateError(.invalidKeyDirectory) {
      try DeviceKeyDirectoryV1(
        revision: Fixture.directoryRevision,
        entries: Array(valid.dropLast()),
        signature: Fixture.signature
      )
    }
    let secondCatalog = try makeWrappedKey(
      keyID: KeyIDV1(purpose: .catalog, epoch: Fixture.catalogKeyID.epoch + 1),
      streamRoute: nil,
      enc: tagged(0xC1, count: 32),
      wrappedKey: tagged(0xC2, count: 48)
    )
    assertStateError(.invalidKeyDirectory) {
      try DeviceKeyDirectoryV1(
        revision: Fixture.directoryRevision,
        entries: [valid[0], secondCatalog] + Array(valid.dropFirst()),
        signature: Fixture.signature
      )
    }
    assertStateError(.invalidKeyDirectory) {
      try DeviceKeyDirectoryV1(
        revision: Fixture.directoryRevision,
        entries: [valid[1], valid[0]] + Array(valid.dropFirst(2)),
        signature: Fixture.signature
      )
    }
  }

  func testKeyReplayAndStreamScopesRejectDuplicatesAndRespectMaximums() throws {
    let validEntries = try defaultKeyEntries()
    let duplicateKey = try makeWrappedKey(
      keyID: validEntries[2].keyID,
      enc: tagged(0xEE, count: 32)
    )
    assertStateError(.invalidKeyDirectory) {
      try DeviceKeyDirectoryV1(
        revision: 1,
        entries: Array(validEntries.prefix(3)) + [duplicateKey, validEntries[3]],
        signature: Fixture.signature
      )
    }

    let base = try makeState(securityState: .active)
    assertStateError(.invalidState) {
      try makeState(
        securityState: .active,
        replayStates: [base.replayStates[0], base.replayStates[0]]
      )
    }
    assertStateError(.invalidState) {
      try makeState(
        securityState: .active,
        streamStates: [base.streamStates[0], base.streamStates[0]]
      )
    }

    let maximumConversations = try (1...1_024).map { index in
      try makeWrappedKey(
        keyID: KeyIDV1(purpose: .conversationDEK, epoch: UInt64(index)),
        streamRoute: identifier16(UInt64(index)),
        enc: tagged(0xA5, count: 32),
        wrappedKey: tagged(0xB5, count: 48)
      )
    }
    let maximumEntries =
      try [
        makeWrappedKey(
          keyID: KeyIDV1(purpose: .catalog, epoch: 1),
          streamRoute: nil,
          enc: tagged(0xA4, count: 32),
          wrappedKey: tagged(0xB4, count: 48)
        )
      ] + maximumConversations + [
        makeWrappedKey(
          keyID: Fixture.senderKeyID,
          streamRoute: nil,
          enc: tagged(0xA6, count: 32),
          wrappedKey: tagged(0xB6, count: 48)
        ),
        makeWrappedKey(
          keyID: Fixture.replyKeyID,
          streamRoute: nil,
          enc: tagged(0xA7, count: 32),
          wrappedKey: tagged(0xB7, count: 48)
        ),
      ]
    let maximumDirectory = try DeviceKeyDirectoryV1(
      revision: Fixture.directoryRevision,
      entries: maximumEntries,
      signature: Fixture.signature
    )
    XCTAssertEqual(maximumDirectory.entries.count, DeviceKeyDirectoryV1.maximumEntries)
    assertStateError(.invalidKeyDirectory) {
      try DeviceKeyDirectoryV1(
        revision: Fixture.directoryRevision,
        entries: maximumEntries + [
          makeWrappedKey(
            keyID: KeyIDV1(
              purpose: .conversationDEK,
              epoch: UInt64(DeviceKeyDirectoryV1.maximumEntries + 1)
            ),
            streamRoute: identifier16(1_025)
          )
        ],
        signature: Fixture.signature
      )
    }

    let maximumReplays = try maximumEntries.filter {
      $0.keyID.purpose != .deviceCommandTx
    }.map { entry in
      try DeviceReplayStateV1(
        scope: DeviceCryptoKeyScopeV1(keyID: entry.keyID, streamRoute: entry.streamRoute),
        window: emptyReplayWindow(),
        status: .active
      )
    }
    let maximumReplayState = try makeState(
      keyDirectory: maximumDirectory,
      senderCounter: makeSender(
        keyID: Fixture.senderKeyID,
        keyDirectoryRevision: maximumDirectory.revision
      ),
      securityState: .active,
      replayStates: maximumReplays,
      streamStates: []
    )
    XCTAssertEqual(maximumReplayState.replayStates.count, DeviceCryptoStateV1.maximumReplayStates)
    assertStateError(.invalidState) {
      try makeState(
        securityState: .active,
        replayStates: Array(
          repeating: base.replayStates[0],
          count: DeviceCryptoStateV1.maximumReplayStates + 1
        )
      )
    }

    let maximumStreams = try (1...DeviceCryptoStateV1.maximumStreamStates).map { index in
      try makeStreamState(
        streamRoute: identifier16(UInt64(index)),
        generation: identifier16(UInt64(index) + 10_000),
        outerCursor: index.isMultiple(of: 2) ? .beforeFirst : .at(UInt64(index)),
        innerCursor: .catalog(.at(UInt64(index)))
      )
    }
    let maximumStreamState = try makeState(
      securityState: .active,
      replayStates: [],
      streamStates: maximumStreams
    )
    XCTAssertEqual(maximumStreamState.streamStates.count, DeviceCryptoStateV1.maximumStreamStates)
    assertStateError(.invalidState) {
      try makeState(
        securityState: .active,
        replayStates: [],
        streamStates: maximumStreams + [
          makeStreamState(streamRoute: identifier16(99_999))
        ]
      )
    }
  }

  func testActiveQuarantinedAndRetiredLifecycleEnforces25HourRetention() throws {
    let scope = DeviceCryptoKeyScopeV1(
      keyID: Fixture.catalogKeyID,
      streamRoute: nil
    )
    XCTAssertNoThrow(
      try DeviceReplayStateV1(scope: scope, window: emptyReplayWindow(), status: .active))
    assertStateError(.invalidReplayState) {
      try DeviceReplayStateV1(
        scope: DeviceCryptoKeyScopeV1(keyID: Fixture.senderKeyID, streamRoute: nil),
        window: emptyReplayWindow(),
        status: .active
      )
    }
    assertStateError(.invalidReplayState) {
      try DeviceReplayStateV1(
        scope: scope,
        window: emptyReplayWindow(),
        status: .quarantined(reason: .nonceReuse, observedAtMS: 0)
      )
    }
    XCTAssertNoThrow(
      try DeviceReplayStateV1(
        scope: scope,
        window: emptyReplayWindow(),
        status: .quarantined(reason: .nonceReuse, observedAtMS: 1)
      ))

    let retiredAtMS: UInt64 = 50_000
    let retention = ReplayWindow.retiredWindowRetentionMilliseconds
    assertStateError(.invalidReplayState) {
      try DeviceReplayStateV1(
        scope: scope,
        window: emptyReplayWindow(),
        status: .retired(
          retiredAtMS: retiredAtMS,
          deleteAfterMS: retiredAtMS + retention - 1
        )
      )
    }
    let retained = try DeviceReplayStateV1(
      scope: scope,
      window: emptyReplayWindow(),
      status: .retired(
        retiredAtMS: retiredAtMS,
        deleteAfterMS: retiredAtMS + retention
      )
    )
    XCTAssertEqual(
      retained.status,
      .retired(retiredAtMS: retiredAtMS, deleteAfterMS: retiredAtMS + retention)
    )
    assertStateError(.invalidReplayState) {
      try DeviceReplayStateV1(
        scope: scope,
        window: emptyReplayWindow(),
        status: .retired(
          retiredAtMS: UInt64.max - retention + 1,
          deleteAfterMS: UInt64.max
        )
      )
    }

    assertStateError(.invalidState) {
      try makeState(
        securityState: .quarantined(
          reason: .authenticatedStateRollback,
          observedAtMS: 0,
          scope: nil
        )
      )
    }
    assertStateError(.invalidState) {
      try makeState(
        securityState: .quarantined(
          reason: .authenticatedStateRollback,
          observedAtMS: 1,
          scope: DeviceCryptoKeyScopeV1(
            keyID: KeyIDV1(purpose: .catalog, epoch: 9_999),
            streamRoute: nil
          )
        )
      )
    }

    let activeState = try makeState(securityState: .active)
    let target = activeState.replayStates[0].scope
    let quarantined = try activeState.quarantining(
      reason: .nonceReuse,
      scope: target,
      observedAtMS: 123_456
    )
    XCTAssertEqual(quarantined.stateRevision, activeState.stateRevision + 1)
    XCTAssertEqual(
      quarantined.securityState,
      .quarantined(reason: .nonceReuse, observedAtMS: 123_456, scope: target)
    )
    XCTAssertEqual(
      quarantined.replayStates[0].status,
      .quarantined(reason: .nonceReuse, observedAtMS: 123_456)
    )
    XCTAssertEqual(
      try DeviceCryptoStateCodec.decode(DeviceCryptoStateCodec.encode(quarantined)),
      quarantined
    )
  }

  func testOuterAndInnerBeforeFirstAndAtCursorsRoundTrip() throws {
    let cursorStates = try [
      makeStreamState(
        streamRoute: identifier16(1),
        generation: identifier16(101),
        outerCursor: .beforeFirst,
        innerCursor: .catalog(.beforeFirst)
      ),
      makeStreamState(
        streamRoute: identifier16(2),
        generation: identifier16(102),
        outerCursor: .beforeFirst,
        innerCursor: .catalog(.at(22))
      ),
      makeStreamState(
        streamRoute: identifier16(3),
        generation: identifier16(103),
        outerCursor: .at(33),
        innerCursor: .conversation(id: "conversation-before", cursor: .beforeFirst)
      ),
      makeStreamState(
        streamRoute: identifier16(4),
        generation: identifier16(104),
        outerCursor: .at(44),
        innerCursor: .conversation(id: "conversation-at", cursor: .at(55))
      ),
    ]
    let state = try makeState(streamStates: cursorStates)
    let decoded = try DeviceCryptoStateCodec.decode(DeviceCryptoStateCodec.encode(state))
    XCTAssertEqual(decoded.streamStates, cursorStates)

    assertStateError(.invalidCursor) {
      try makeStreamState(innerCursor: .conversation(id: "", cursor: .beforeFirst))
    }
    assertStateError(.invalidCursor) {
      try makeStreamState(
        innerCursor: .conversation(
          id: String(repeating: "a", count: 8 * 1_024 + 1),
          cursor: .at(1)
        )
      )
    }
  }

  func testCodecRejectsMalformedTrailingVersionLengthEnumsAndNoncanonicalFields() throws {
    let encoded = try DeviceCryptoStateCodec.encode(makeState())
    let offsets = try inspectLayout(encoded)

    assertDecodeRejected(Data())
    assertMutatedDecodeRejected(encoded) { $0[0] ^= 0xFF }
    assertMutatedDecodeRejected(encoded) { $0[5] = 2 }
    assertMutatedDecodeRejected(encoded) { $0[6] = 1 }
    assertMutatedDecodeRejected(encoded) { $0[11] &+= 1 }
    assertDecodeRejected(Data(encoded.dropLast()))
    var trailing = encoded
    trailing.append(0)
    assertDecodeRejected(trailing)

    for enumOffset in [
      offsets.firstKeyPurpose,
      offsets.securityStatus,
      offsets.securityReason,
      offsets.firstReplayStatus,
      offsets.firstReplayReason,
      offsets.firstReplayHighWaterTag,
      offsets.firstOuterCursorTag,
      offsets.firstInnerCursorTag,
    ] {
      assertMutatedDecodeRejected(encoded) { $0[enumOffset] = 0xFF }
    }

    XCTAssertEqual(encoded[offsets.firstKeyStreamOptionalTag], 0)
    assertMutatedDecodeRejected(encoded) {
      $0[offsets.firstKeyStreamOptionalValue] = 1
    }
    assertMutatedDecodeRejected(encoded) {
      $0[offsets.firstKeyStreamOptionalTag] = 2
    }

    XCTAssertEqual(encoded[offsets.firstReplayHighWaterTag], 0)
    assertMutatedDecodeRejected(encoded) {
      $0[offsets.firstReplayHighWaterValue + 7] = 1
    }

    XCTAssertEqual(encoded[offsets.firstOuterCursorTag], 0)
    assertMutatedDecodeRejected(encoded) {
      $0[offsets.firstOuterCursorValue + 7] = 1
    }

    assertMutatedDecodeRejected(encoded) {
      for index in offsets.firstKeyEncLength..<(offsets.firstKeyEncLength + 4) {
        $0[index] = 0xFF
      }
    }

    let activeEncoded = try DeviceCryptoStateCodec.encode(makeState(securityState: .active))
    let activeOffsets = try inspectLayout(activeEncoded)
    XCTAssertEqual(activeEncoded[activeOffsets.securityStatus], 0)
    assertMutatedDecodeRejected(activeEncoded) {
      $0[activeOffsets.securityReason] = DeviceCryptoSecurityReason.nonceReuse.rawValue
    }
  }

  func testCanonicalCommitmentCoversCounterReplayCursorAndEveryTrustAxis() throws {
    let baseline = try makeState()
    let baselineCommitment = try canonicalCommitment(baseline)

    let counterVariants = try [
      makeState(
        senderCounter: makeSender(
          noncePrefix: Data([0x10, 0x20, 0x30, 0x41])
        )
      ),
      makeState(
        senderCounter: makeSender(
          reservedHighWater: CounterBlock.size * 3,
          reservationID: tagged(0xD2, count: 16)
        )
      ),
    ]

    var replayWithCounter = baseline.replayStates
    replayWithCounter[0] = try DeviceReplayStateV1(
      scope: replayWithCounter[0].scope,
      window: ReplayWindowSnapshot(
        highWater: 1,
        floor: 0,
        entries: [ReplayWindowEntry(counter: 1, ciphertextHash: tagged(0xA7, count: 32))]
      ),
      status: replayWithCounter[0].status
    )
    var replayWithStatus = baseline.replayStates
    replayWithStatus[0] = try DeviceReplayStateV1(
      scope: replayWithStatus[0].scope,
      window: replayWithStatus[0].window,
      status: .quarantined(reason: .nonceReuse, observedAtMS: 333)
    )
    let replayVariants = try [
      makeState(replayStates: replayWithCounter),
      makeState(replayStates: replayWithStatus),
    ]

    var cursorWithOuter = baseline.streamStates
    cursorWithOuter[0] = try makeStreamState(
      streamRoute: cursorWithOuter[0].streamRoute,
      generation: cursorWithOuter[0].generation,
      outerCursor: .at(1),
      innerCursor: cursorWithOuter[0].innerCursor
    )
    var cursorWithInner = baseline.streamStates
    cursorWithInner[0] = try makeStreamState(
      streamRoute: cursorWithInner[0].streamRoute,
      generation: cursorWithInner[0].generation,
      outerCursor: cursorWithInner[0].outerCursor,
      innerCursor: .catalog(.at(18))
    )
    var cursorWithGeneration = baseline.streamStates
    cursorWithGeneration[0] = try makeStreamState(
      streamRoute: cursorWithGeneration[0].streamRoute,
      generation: tagged(0x7A, count: 16),
      outerCursor: cursorWithGeneration[0].outerCursor,
      innerCursor: cursorWithGeneration[0].innerCursor
    )
    let cursorVariants = try [
      makeState(streamStates: cursorWithOuter),
      makeState(streamStates: cursorWithInner),
      makeState(streamStates: cursorWithGeneration),
    ]

    let trustVariants = try [
      makeState(trustScope: makeTrust(relayServerID: tagged(0x12, count: 16))),
      makeState(trustScope: makeTrust(machineRootFingerprint: tagged(0x23, count: 32))),
      makeState(trustScope: makeTrust(machineRoute: tagged(0x34, count: 16))),
      makeState(trustScope: makeTrust(deviceRoute: tagged(0x45, count: 16))),
      makeState(trustScope: makeTrust(grantSerial: Fixture.grantSerial + 1)),
      makeState(trustScope: makeTrust(trustEpoch: Fixture.trustEpoch + 1)),
    ]

    let groups = [
      ("counter", counterVariants),
      ("replay", replayVariants),
      ("cursor", cursorVariants),
      ("trust", trustVariants),
    ]
    for (axis, variants) in groups {
      for (index, variant) in variants.enumerated() {
        XCTAssertNotEqual(
          try canonicalCommitment(variant),
          baselineCommitment,
          "完整 canonical commitment 必须绑定 \(axis)[\(index)]"
        )
      }
    }
  }
}

private enum Fixture {
  static let relayServerID = tagged(0x11, count: 16)
  static let machineRootFingerprint = tagged(0x22, count: 32)
  static let machineRoute = tagged(0x33, count: 16)
  static let deviceRoute = tagged(0x44, count: 16)
  static let streamRouteA = tagged(0x51, count: 16)
  static let streamRouteB = tagged(0x52, count: 16)
  static let streamRouteC = tagged(0x53, count: 16)
  static let generationA = tagged(0x61, count: 16)
  static let generationB = tagged(0x62, count: 16)
  static let signature = tagged(0x91, count: 64)
  static let reservationID = tagged(0xD1, count: 16)
  static let grantSerial: UInt64 = 5
  static let trustEpoch: UInt64 = 6
  static let directoryRevision: UInt64 = 17
  static let senderEpoch: UInt64 = 101
  static let senderKeyID = KeyIDV1(purpose: .deviceCommandTx, epoch: senderEpoch)
  static let catalogKeyID = KeyIDV1(purpose: .catalog, epoch: 102)
  static let conversationKeyID = KeyIDV1(purpose: .conversationDEK, epoch: 103)
  static let replyKeyID = KeyIDV1(purpose: .deviceReplyTx, epoch: 104)
}

private func tagged(_ byte: UInt8, count: Int) -> Data {
  Data(repeating: byte, count: count)
}

private func identifier16(_ value: UInt64) -> Data {
  precondition(value > 0)
  var result = Data(repeating: 0, count: 16)
  for byteIndex in 0..<8 {
    result[15 - byteIndex] = UInt8(truncatingIfNeeded: value >> UInt64(byteIndex * 8))
  }
  return result
}

private func makeTrust(
  relayServerID: Data = Fixture.relayServerID,
  machineRootFingerprint: Data = Fixture.machineRootFingerprint,
  machineRoute: Data = Fixture.machineRoute,
  deviceRoute: Data = Fixture.deviceRoute,
  grantSerial: UInt64 = Fixture.grantSerial,
  trustEpoch: UInt64 = Fixture.trustEpoch
) throws -> DeviceCryptoTrustScopeV1 {
  try DeviceCryptoTrustScopeV1(
    relayServerID: relayServerID,
    machineRootFingerprint: machineRootFingerprint,
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    grantSerial: grantSerial,
    trustEpoch: trustEpoch
  )
}

private func makeWrappedKey(
  keyID: KeyIDV1 = KeyIDV1(purpose: .deviceCommandTx, epoch: Fixture.senderEpoch),
  deviceRoute: Data = Fixture.deviceRoute,
  streamRoute: Data? = nil,
  enc: Data = tagged(0xA1, count: DeviceWrappedKeyV1.encapsulatedKeyBytes),
  wrappedKey: Data = tagged(0xB1, count: DeviceWrappedKeyV1.wrappedKeyBytes)
) throws -> DeviceWrappedKeyV1 {
  try DeviceWrappedKeyV1(
    keyID: keyID,
    deviceRoute: deviceRoute,
    streamRoute: streamRoute,
    enc: enc,
    wrappedKey: wrappedKey
  )
}

private func defaultKeyEntries(deviceRoute: Data = Fixture.deviceRoute) throws
  -> [DeviceWrappedKeyV1]
{
  try [
    makeWrappedKey(
      keyID: Fixture.catalogKeyID,
      deviceRoute: deviceRoute,
      streamRoute: nil,
      enc: tagged(0xA1, count: DeviceWrappedKeyV1.encapsulatedKeyBytes),
      wrappedKey: tagged(0xB1, count: DeviceWrappedKeyV1.wrappedKeyBytes)
    ),
    makeWrappedKey(
      keyID: Fixture.conversationKeyID,
      deviceRoute: deviceRoute,
      streamRoute: Fixture.streamRouteB,
      enc: tagged(0xA2, count: DeviceWrappedKeyV1.encapsulatedKeyBytes),
      wrappedKey: tagged(0xB2, count: DeviceWrappedKeyV1.wrappedKeyBytes)
    ),
    makeWrappedKey(
      keyID: KeyIDV1(purpose: .deviceCommandTx, epoch: Fixture.senderEpoch),
      deviceRoute: deviceRoute,
      streamRoute: nil,
      enc: tagged(0xA3, count: DeviceWrappedKeyV1.encapsulatedKeyBytes),
      wrappedKey: tagged(0xB3, count: DeviceWrappedKeyV1.wrappedKeyBytes)
    ),
    makeWrappedKey(
      keyID: Fixture.replyKeyID,
      deviceRoute: deviceRoute,
      streamRoute: nil,
      enc: tagged(0xA4, count: DeviceWrappedKeyV1.encapsulatedKeyBytes),
      wrappedKey: tagged(0xB4, count: DeviceWrappedKeyV1.wrappedKeyBytes)
    ),
  ]
}

private func makeDirectory(
  deviceRoute: Data = Fixture.deviceRoute,
  revision: UInt64 = Fixture.directoryRevision,
  entries: [DeviceWrappedKeyV1]? = nil
) throws -> DeviceKeyDirectoryV1 {
  try DeviceKeyDirectoryV1(
    revision: revision,
    entries: try entries ?? defaultKeyEntries(deviceRoute: deviceRoute),
    signature: Fixture.signature
  )
}

private func makeSender(
  keyID: KeyIDV1 = KeyIDV1(purpose: .deviceCommandTx, epoch: Fixture.senderEpoch),
  keyDirectoryRevision: UInt64 = Fixture.directoryRevision,
  noncePrefix: Data = Data([0x10, 0x20, 0x30, 0x40]),
  reservedHighWater: UInt64 = CounterBlock.size * 2,
  reservationID: Data = Fixture.reservationID
) throws -> DeviceSenderCounterV1 {
  try DeviceSenderCounterV1(
    keyID: keyID,
    keyDirectoryRevision: keyDirectoryRevision,
    noncePrefix: noncePrefix,
    reservedHighWater: reservedHighWater,
    reservationID: reservationID
  )
}

private func emptyReplayWindow() -> ReplayWindowSnapshot {
  ReplayWindowSnapshot(highWater: nil, floor: 0, entries: [])
}

private func defaultReplayStates() throws -> [DeviceReplayStateV1] {
  let retiredAtMS: UInt64 = 70_000
  return try [
    DeviceReplayStateV1(
      scope: DeviceCryptoKeyScopeV1(
        keyID: Fixture.catalogKeyID,
        streamRoute: nil
      ),
      window: emptyReplayWindow(),
      status: .active
    ),
    DeviceReplayStateV1(
      scope: DeviceCryptoKeyScopeV1(
        keyID: Fixture.conversationKeyID,
        streamRoute: Fixture.streamRouteB
      ),
      window: ReplayWindowSnapshot(
        highWater: 7,
        floor: 0,
        entries: [ReplayWindowEntry(counter: 7, ciphertextHash: tagged(0xC2, count: 32))]
      ),
      status: .quarantined(reason: .nonceReuse, observedAtMS: 80_000)
    ),
    DeviceReplayStateV1(
      scope: DeviceCryptoKeyScopeV1(keyID: Fixture.replyKeyID, streamRoute: nil),
      window: emptyReplayWindow(),
      status: .retired(
        retiredAtMS: retiredAtMS,
        deleteAfterMS: retiredAtMS + ReplayWindow.retiredWindowRetentionMilliseconds
      )
    ),
  ]
}

private func makeStreamState(
  streamRoute: Data = Fixture.streamRouteA,
  generation: Data = Fixture.generationA,
  outerCursor: StreamCursor = .beforeFirst,
  innerCursor: DeviceInnerCursorV1 = .catalog(.at(17))
) throws -> DeviceStreamCursorStateV1 {
  try DeviceStreamCursorStateV1(
    streamRoute: streamRoute,
    generation: generation,
    outerCursor: outerCursor,
    innerCursor: innerCursor
  )
}

private func defaultStreamStates() throws -> [DeviceStreamCursorStateV1] {
  try [
    makeStreamState(
      streamRoute: Fixture.streamRouteA,
      generation: Fixture.generationA,
      outerCursor: .beforeFirst,
      innerCursor: .catalog(.at(17))
    ),
    makeStreamState(
      streamRoute: Fixture.streamRouteB,
      generation: Fixture.generationB,
      outerCursor: .at(18),
      innerCursor: .conversation(id: "conversation-1", cursor: .beforeFirst)
    ),
  ]
}

private func makeState(
  stateRevision: UInt64 = 41,
  trustScope: DeviceCryptoTrustScopeV1? = nil,
  keyDirectory: DeviceKeyDirectoryV1? = nil,
  senderCounter: DeviceSenderCounterV1? = nil,
  securityState: DeviceMachineSecurityStateV1? = nil,
  replayStates: [DeviceReplayStateV1]? = nil,
  streamStates: [DeviceStreamCursorStateV1]? = nil
) throws -> DeviceCryptoStateV1 {
  let trust = try trustScope ?? makeTrust()
  let directory = try keyDirectory ?? makeDirectory(deviceRoute: trust.deviceRoute)
  let sender =
    try senderCounter
    ?? makeSender(keyDirectoryRevision: directory.revision)
  let replays = try replayStates ?? defaultReplayStates()
  let security =
    securityState
    ?? .quarantined(
      reason: .keyRevisionRollback,
      observedAtMS: 90_000,
      scope: DeviceCryptoKeyScopeV1(
        keyID: Fixture.conversationKeyID,
        streamRoute: Fixture.streamRouteB
      )
    )
  return try DeviceCryptoStateV1(
    stateRevision: stateRevision,
    trustScope: trust,
    keyDirectory: directory,
    senderCounter: sender,
    securityState: security,
    replayStates: replays,
    streamStates: try streamStates ?? defaultStreamStates()
  )
}

private func canonicalCommitment(_ state: DeviceCryptoStateV1) throws -> Data {
  try CryptoStateSnapshot(state).commitment
}

private func assertStateError<T>(
  _ expected: DeviceCryptoStateError,
  file: StaticString = #filePath,
  line: UInt = #line,
  _ operation: () throws -> T
) {
  XCTAssertThrowsError(try operation(), file: file, line: line) { error in
    XCTAssertEqual(error as? DeviceCryptoStateError, expected, file: file, line: line)
  }
}

private func assertDecodeRejected(
  _ encoded: Data,
  file: StaticString = #filePath,
  line: UInt = #line
) {
  XCTAssertThrowsError(
    try DeviceCryptoStateCodec.decode(encoded),
    "畸形或非 canonical state 必须 fail closed",
    file: file,
    line: line
  )
}

private func assertMutatedDecodeRejected(
  _ encoded: Data,
  file: StaticString = #filePath,
  line: UInt = #line,
  mutate: (inout Data) -> Void
) {
  var mutated = encoded
  mutate(&mutated)
  assertDecodeRejected(mutated, file: file, line: line)
}

private struct DeviceStateLayoutOffsets {
  let firstKeyPurpose: Int
  let firstKeyStreamOptionalTag: Int
  let firstKeyStreamOptionalValue: Int
  let firstKeyEncLength: Int
  let securityStatus: Int
  let securityReason: Int
  let firstReplayStatus: Int
  let firstReplayReason: Int
  let firstReplayHighWaterTag: Int
  let firstReplayHighWaterValue: Int
  let firstOuterCursorTag: Int
  let firstOuterCursorValue: Int
  let firstInnerCursorTag: Int
}

private enum LayoutInspectionError: Error {
  case truncated
  case emptyFixture
}

private struct LayoutReader {
  let data: Data
  var offset: Int

  mutating func skip(_ count: Int) throws {
    let end = offset.addingReportingOverflow(count)
    guard count >= 0, !end.overflow, end.partialValue <= data.count else {
      throw LayoutInspectionError.truncated
    }
    offset = end.partialValue
  }

  mutating func readU32() throws -> Int {
    guard offset + 4 <= data.count else { throw LayoutInspectionError.truncated }
    var value: UInt32 = 0
    for byte in data[offset..<(offset + 4)] {
      value = (value << 8) | UInt32(byte)
    }
    offset += 4
    return Int(value)
  }

  mutating func skipLengthPrefixed() throws {
    let count = try readU32()
    try skip(count)
  }
}

private func inspectLayout(_ encoded: Data) throws -> DeviceStateLayoutOffsets {
  var reader = LayoutReader(data: encoded, offset: 12)
  try reader.skip(8 + 16 + 32 + 16 + 16 + 8 + 8)
  try reader.skip(8)
  let keyCount = try reader.readU32()
  guard keyCount > 0 else { throw LayoutInspectionError.emptyFixture }

  var firstKeyPurpose: Int?
  var firstKeyStreamOptionalTag: Int?
  var firstKeyStreamOptionalValue: Int?
  var firstKeyEncLength: Int?
  for index in 0..<keyCount {
    if index == 0 { firstKeyPurpose = reader.offset }
    try reader.skip(1 + 7 + 8 + 16)
    if index == 0 { firstKeyStreamOptionalTag = reader.offset }
    try reader.skip(1)
    if index == 0 { firstKeyStreamOptionalValue = reader.offset }
    try reader.skip(16)
    if index == 0 { firstKeyEncLength = reader.offset }
    try reader.skipLengthPrefixed()
    try reader.skipLengthPrefixed()
  }
  try reader.skip(64)
  try reader.skip(1 + 7 + 8 + 8 + 4 + 4 + 8 + 16)

  let securityStatus = reader.offset
  let securityReason = securityStatus + 1
  try reader.skip(1 + 1 + 6 + 8 + 1 + 1 + 6 + 8 + 1 + 16)

  let replayCount = try reader.readU32()
  guard replayCount > 0 else { throw LayoutInspectionError.emptyFixture }
  var firstReplayStatus: Int?
  var firstReplayReason: Int?
  var firstReplayHighWaterTag: Int?
  var firstReplayHighWaterValue: Int?
  for index in 0..<replayCount {
    try reader.skip(1 + 7 + 8 + 1 + 16)
    if index == 0 {
      firstReplayStatus = reader.offset
      firstReplayReason = reader.offset + 1
    }
    try reader.skip(1 + 1 + 6 + 8 + 8)
    if index == 0 {
      firstReplayHighWaterTag = reader.offset
      firstReplayHighWaterValue = reader.offset + 8
    }
    try reader.skip(1 + 7 + 8 + 8)
    let entryCount = try reader.readU32()
    try reader.skip(entryCount * (8 + 32))
  }

  let streamCount = try reader.readU32()
  guard streamCount > 0 else { throw LayoutInspectionError.emptyFixture }
  var firstOuterCursorTag: Int?
  var firstOuterCursorValue: Int?
  var firstInnerCursorTag: Int?
  for index in 0..<streamCount {
    try reader.skip(16 + 16)
    if index == 0 {
      firstOuterCursorTag = reader.offset
      firstOuterCursorValue = reader.offset + 8
    }
    try reader.skip(1 + 7 + 8)
    if index == 0 { firstInnerCursorTag = reader.offset }
    let innerTag = encoded[reader.offset]
    try reader.skip(1 + 7)
    switch innerTag {
    case 0:
      try reader.skip(1 + 7 + 8)
    case 1:
      try reader.skipLengthPrefixed()
      try reader.skip(1 + 7 + 8)
    default:
      throw LayoutInspectionError.truncated
    }
  }

  guard let firstKeyPurpose,
    let firstKeyStreamOptionalTag,
    let firstKeyStreamOptionalValue,
    let firstKeyEncLength,
    let firstReplayStatus,
    let firstReplayReason,
    let firstReplayHighWaterTag,
    let firstReplayHighWaterValue,
    let firstOuterCursorTag,
    let firstOuterCursorValue,
    let firstInnerCursorTag
  else {
    throw LayoutInspectionError.emptyFixture
  }
  return DeviceStateLayoutOffsets(
    firstKeyPurpose: firstKeyPurpose,
    firstKeyStreamOptionalTag: firstKeyStreamOptionalTag,
    firstKeyStreamOptionalValue: firstKeyStreamOptionalValue,
    firstKeyEncLength: firstKeyEncLength,
    securityStatus: securityStatus,
    securityReason: securityReason,
    firstReplayStatus: firstReplayStatus,
    firstReplayReason: firstReplayReason,
    firstReplayHighWaterTag: firstReplayHighWaterTag,
    firstReplayHighWaterValue: firstReplayHighWaterValue,
    firstOuterCursorTag: firstOuterCursorTag,
    firstOuterCursorValue: firstOuterCursorValue,
    firstInnerCursorTag: firstInnerCursorTag
  )
}
