import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class KeyUpdateSetVerifierTests: XCTestCase {
  func testRustGoldenVectorMatchesCanonicalSetAndInnerCarriers() throws {
    let vector = try loadKeyUpdateSetVector()
    let canonical = try keyUpdateSetVectorData("canonicalHex", in: vector)
    let expectedUpdates = try keyUpdateSetVectorDataArray(
      "updateCanonicalHexes",
      in: vector
    )

    let set = try KeyUpdateSetCanonicalCodec.decode(canonical)

    XCTAssertEqual(try KeyUpdateSetCanonicalCodec.encode(set), canonical)
    XCTAssertEqual(
      CanonicalCodec.sha256(canonical),
      try keyUpdateSetVectorData("sha256Hex", in: vector)
    )
    XCTAssertEqual(
      set.keyDirectoryRevision,
      try keyUpdateSetVectorUInt64("keyDirectoryRevision", in: vector)
    )
    XCTAssertEqual(
      set.deviceRoute,
      try keyUpdateSetVectorData("deviceRouteHex", in: vector)
    )
    XCTAssertEqual(try set.updates.map(KeyUpdateCanonicalCodec.encode), expectedUpdates)
    XCTAssertEqual(set.updates.map(\.keyID.purpose), [.catalog, .conversationDEK])
  }

  func testStrictCodecRoundTripsAndRejectsOrderDuplicateTrailingAndInnerOverflow() throws {
    let deviceRoute = Data(repeating: 0x22, count: 16)
    let catalog = try syntheticUpdate(
      purpose: .catalog,
      streamRoute: nil,
      marker: 0x31,
      deviceRoute: deviceRoute
    )
    let conversationA = try syntheticUpdate(
      purpose: .conversationDEK,
      streamRoute: route(1),
      marker: 0x32,
      deviceRoute: deviceRoute
    )
    let conversationB = try syntheticUpdate(
      purpose: .conversationDEK,
      streamRoute: route(2),
      marker: 0x33,
      deviceRoute: deviceRoute
    )
    let conversationSameSlotNextEpoch = try syntheticUpdate(
      purpose: .conversationDEK,
      streamRoute: route(1),
      marker: 0x35,
      deviceRoute: deviceRoute,
      epoch: 5
    )
    let command = try syntheticUpdate(
      purpose: .deviceCommandTx,
      streamRoute: nil,
      marker: 0x34,
      deviceRoute: deviceRoute
    )
    let set = try CanonicalKeyUpdateSetV1(
      keyDirectoryRevision: 8,
      deviceRoute: deviceRoute,
      updates: [catalog, conversationA, conversationB, command]
    )
    let canonical = try KeyUpdateSetCanonicalCodec.encode(set)

    XCTAssertEqual(try KeyUpdateSetCanonicalCodec.decode(canonical), set)
    XCTAssertEqual(try KeyUpdateSetCanonicalCodec.encode(set), canonical)
    XCTAssertLessThan(canonical.count, KeyUpdateSetCanonicalCodec.maximumCanonicalBytes)

    XCTAssertThrowsError(
      try CanonicalKeyUpdateSetV1(
        keyDirectoryRevision: 8,
        deviceRoute: deviceRoute,
        updates: [conversationB, conversationA]
      ))
    XCTAssertThrowsError(
      try CanonicalKeyUpdateSetV1(
        keyDirectoryRevision: 8,
        deviceRoute: deviceRoute,
        updates: [conversationA, conversationA]
      ))
    XCTAssertThrowsError(
      try CanonicalKeyUpdateSetV1(
        keyDirectoryRevision: 8,
        deviceRoute: deviceRoute,
        updates: [conversationA, conversationSameSlotNextEpoch]
      ))

    let encodedA = try KeyUpdateCanonicalCodec.encode(conversationA)
    let encodedB = try KeyUpdateCanonicalCodec.encode(conversationB)
    XCTAssertThrowsError(
      try KeyUpdateSetCanonicalCodec.decode(
        rawSet(
          revision: 8,
          deviceRoute: deviceRoute,
          updateCarriers: [encodedB, encodedA]
        )))
    XCTAssertThrowsError(
      try KeyUpdateSetCanonicalCodec.decode(
        rawSet(
          revision: 8,
          deviceRoute: deviceRoute,
          updateCarriers: [encodedA, encodedA]
        )))

    var trailing = canonical
    trailing.append(0)
    XCTAssertThrowsError(try KeyUpdateSetCanonicalCodec.decode(trailing))
    XCTAssertThrowsError(
      try KeyUpdateSetCanonicalCodec.decode(
        rawSet(
          revision: 8,
          deviceRoute: deviceRoute,
          updateCarriers: [
            Data(
              repeating: 0xA5,
              count: KeyUpdateCanonicalCodec.maximumCanonicalBytes + 1
            )
          ]
        ))
    ) { error in
      XCTAssertEqual(error as? KeyUpdateSetVerifierError, .sizeLimit)
    }
    XCTAssertThrowsError(
      try KeyUpdateSetCanonicalCodec.decode(
        rawSet(revision: 8, deviceRoute: deviceRoute, updateCarriers: [])
      )
    ) { error in
      XCTAssertEqual(error as? KeyUpdateSetVerifierError, .sizeLimit)
    }
  }

  func testGlobalRevisionDeviceAndPerUpdateBindingAreExact() throws {
    let deviceRoute = Data(repeating: 0x22, count: 16)
    let update = try syntheticUpdate(
      purpose: .catalog,
      streamRoute: nil,
      marker: 0x41,
      deviceRoute: deviceRoute
    )

    XCTAssertThrowsError(
      try CanonicalKeyUpdateSetV1(
        keyDirectoryRevision: 9,
        deviceRoute: deviceRoute,
        updates: [update]
      ))
    XCTAssertThrowsError(
      try CanonicalKeyUpdateSetV1(
        keyDirectoryRevision: 8,
        deviceRoute: Data(repeating: 0x23, count: 16),
        updates: [update]
      ))
    XCTAssertThrowsError(
      try CanonicalKeyUpdateSetV1(
        keyDirectoryRevision: 8,
        deviceRoute: Data(repeating: 0, count: 16),
        updates: [update]
      ))
    XCTAssertThrowsError(
      try CanonicalKeyUpdateSetV1(
        keyDirectoryRevision: 0,
        deviceRoute: deviceRoute,
        updates: [update]
      ))
  }

  func testCountAndCanonicalByteCapsAreHardBounds() throws {
    let deviceRoute = Data(repeating: 0x22, count: 16)
    let maximum = try (1...CanonicalKeyUpdateSetV1.maximumUpdates).map { index in
      try syntheticUpdate(
        purpose: .conversationDEK,
        streamRoute: route(UInt64(index)),
        marker: UInt8(truncatingIfNeeded: index | 1),
        deviceRoute: deviceRoute
      )
    }
    let maximumSet = try CanonicalKeyUpdateSetV1(
      keyDirectoryRevision: 8,
      deviceRoute: deviceRoute,
      updates: maximum
    )
    let canonical = try KeyUpdateSetCanonicalCodec.encode(maximumSet)
    XCTAssertEqual(try KeyUpdateSetCanonicalCodec.decode(canonical).updates.count, 1_027)
    XCTAssertLessThanOrEqual(canonical.count, KeyUpdateSetCanonicalCodec.maximumCanonicalBytes)

    let overflow = try syntheticUpdate(
      purpose: .conversationDEK,
      streamRoute: route(UInt64(CanonicalKeyUpdateSetV1.maximumUpdates + 1)),
      marker: 0xF1,
      deviceRoute: deviceRoute
    )
    XCTAssertThrowsError(
      try CanonicalKeyUpdateSetV1(
        keyDirectoryRevision: 8,
        deviceRoute: deviceRoute,
        updates: maximum + [overflow]
      ))

    XCTAssertThrowsError(
      try KeyUpdateSetCanonicalCodec.decode(
        Data(
          repeating: 0,
          count: KeyUpdateSetCanonicalCodec.maximumCanonicalBytes + 1
        ))
    ) { error in
      XCTAssertEqual(error as? KeyUpdateSetVerifierError, .sizeLimit)
    }
    XCTAssertThrowsError(
      try KeyUpdateSetCanonicalCodec.decode(
        canonical,
        maximumEncodedBytes: canonical.count - 1
      )
    ) { error in
      XCTAssertEqual(error as? KeyUpdateSetVerifierError, .sizeLimit)
    }
  }

  func testVerifierOpensEverySignedCarrierAndRetainsOpaqueSecretRelations() throws {
    let fixture = try KeyUpdateSetCryptoFixture()
    let sameSecret = Data(repeating: 0x51, count: 32)
    let catalog = try fixture.signedUpdate(
      purpose: .catalog,
      streamRoute: nil,
      rawKey: sameSecret
    )
    let conversation = try fixture.signedUpdate(
      purpose: .conversationDEK,
      streamRoute: route(7),
      rawKey: Data(repeating: 0x52, count: 32)
    )
    let reply = try fixture.signedUpdate(
      purpose: .deviceReplyTx,
      streamRoute: nil,
      rawKey: sameSecret
    )
    let set = try CanonicalKeyUpdateSetV1(
      keyDirectoryRevision: fixture.revision,
      deviceRoute: fixture.deviceRoute,
      updates: [catalog, conversation, reply]
    )
    let canonical = try KeyUpdateSetCanonicalCodec.encode(set)

    let verified = try fixture.setVerifier.verifyAndOpen(
      canonicalBytes: canonical,
      expectedRevision: fixture.revision
    )

    XCTAssertEqual(verified.keyDirectoryRevision, fixture.revision)
    XCTAssertEqual(verified.deviceRoute, fixture.deviceRoute)
    XCTAssertEqual(verified.canonicalBytes, canonical)
    XCTAssertEqual(verified.updates.count, 3)
    XCTAssertEqual(
      verified.updates.map(\.canonicalBytes),
      try set.updates.map(KeyUpdateCanonicalCodec.encode)
    )
    XCTAssertTrue(try verified.updatesShareSecret(at: 0, 2))
    XCTAssertFalse(try verified.updatesShareSecret(at: 0, 1))
    XCTAssertThrowsError(try verified.updatesShareSecret(at: -1, 0)) { error in
      XCTAssertEqual(error as? KeyUpdateSetVerifierError, .invalidIndex)
    }
    for debug in [String(reflecting: verified)] + verified.updates.map({ String(reflecting: $0) }) {
      XCTAssertTrue(debug.contains("<redacted>"), debug)
      XCTAssertFalse(debug.contains(sameSecret.hexString), debug)
    }
  }

  func testVerifierRejectsExpectedRevisionSignatureAndResignedHPKETamper() throws {
    let fixture = try KeyUpdateSetCryptoFixture()
    let signed = try fixture.signedUpdate(
      purpose: .catalog,
      streamRoute: nil,
      rawKey: Data(repeating: 0x61, count: 32)
    )

    let validSet = try CanonicalKeyUpdateSetV1(
      keyDirectoryRevision: fixture.revision,
      deviceRoute: fixture.deviceRoute,
      updates: [signed]
    )
    let validCanonical = try KeyUpdateSetCanonicalCodec.encode(validSet)
    XCTAssertThrowsError(
      try fixture.setVerifier.verifyAndOpen(
        canonicalBytes: validCanonical,
        expectedRevision: fixture.revision + 1
      )
    ) { error in
      XCTAssertEqual(error as? KeyUpdateSetVerifierError, .revisionMismatch)
    }

    var badSignature = signed.signature
    badSignature[0] ^= 1
    let forged = try replacing(signed, signature: badSignature)
    let forgedSet = try CanonicalKeyUpdateSetV1(
      keyDirectoryRevision: fixture.revision,
      deviceRoute: fixture.deviceRoute,
      updates: [forged]
    )
    XCTAssertThrowsError(
      try fixture.setVerifier.verifyAndOpen(
        canonicalBytes: KeyUpdateSetCanonicalCodec.encode(forgedSet),
        expectedRevision: fixture.revision
      )
    ) { error in
      XCTAssertEqual(error as? KeyDirectoryVerifierError, .badSignature)
    }

    let hpkeTamper = try fixture.signedUpdate(
      purpose: .catalog,
      streamRoute: nil,
      rawKey: Data(repeating: 0x61, count: 32),
      tamperWrappedKeyBeforeSigning: true
    )
    let tamperedSet = try CanonicalKeyUpdateSetV1(
      keyDirectoryRevision: fixture.revision,
      deviceRoute: fixture.deviceRoute,
      updates: [hpkeTamper]
    )
    XCTAssertThrowsError(
      try fixture.setVerifier.verifyAndOpen(
        canonicalBytes: KeyUpdateSetCanonicalCodec.encode(tamperedSet),
        expectedRevision: fixture.revision
      )
    ) { error in
      XCTAssertEqual(error as? KeyDirectoryVerifierError, .hpkeOpenFailed)
    }
  }

  func testSingleUpdateSetDoesNotClaimRosterCompleteness() throws {
    let fixture = try KeyUpdateSetCryptoFixture()
    let update = try fixture.signedUpdate(
      purpose: .catalog,
      streamRoute: nil,
      rawKey: Data(repeating: 0x71, count: 32)
    )
    let set = try CanonicalKeyUpdateSetV1(
      keyDirectoryRevision: fixture.revision,
      deviceRoute: fixture.deviceRoute,
      updates: [update]
    )

    let verified = try fixture.setVerifier.verifyAndOpen(
      canonicalBytes: KeyUpdateSetCanonicalCodec.encode(set),
      expectedRevision: fixture.revision
    )
    XCTAssertEqual(verified.updates.count, 1)
    XCTAssertEqual(verified.updates[0].keyID.purpose, .catalog)
  }

  func testDurableStageIsWholeSetIdempotentAndRejectsCrossIdentitySecretReuse() throws {
    let fixture = try KeyUpdateSetCryptoFixture()
    let bootstrap = try fixture.signedDirectory(
      revision: 7,
      materials: lifecycleBootstrapMaterials()
    )
    let state = try lifecycleState(fixture: fixture, directory: bootstrap.directory)
    let canonical = try fixture.signedUpdateSet(
      revision: 8,
      materials: [
        LifecycleTestMaterial(purpose: .catalog, epoch: 2, streamRoute: nil, rawKeyByte: 0x51),
        LifecycleTestMaterial(
          purpose: .deviceCommandTx,
          epoch: 1,
          streamRoute: nil,
          rawKeyByte: 0x42
        ),
        LifecycleTestMaterial(
          purpose: .deviceReplyTx,
          epoch: 1,
          streamRoute: nil,
          rawKeyByte: 0x43
        ),
      ]
    )

    let staged = try fixture.setVerifier.prepareDurableStage(
      state: state,
      canonicalBytes: canonical,
      expectedConversationRoutes: []
    )
    XCTAssertEqual(staged.stateRevision, 2)
    XCTAssertEqual(staged.senderCounter.keyDirectoryRevision, 7)
    XCTAssertEqual(staged.keyLifecycle?.activeRevision, 7)
    XCTAssertEqual(staged.keyLifecycle?.stagedTransition?.toRevision, 8)
    XCTAssertEqual(
      staged.keyLifecycle?.slot(purpose: .catalog, streamRoute: nil)?.staged?.keyID.epoch,
      2
    )
    XCTAssertEqual(
      try fixture.setVerifier.prepareDurableStage(
        state: staged,
        canonicalBytes: canonical,
        expectedConversationRoutes: []
      ),
      staged
    )
    _ = try fixture.setVerifier.auditColdOpen(
      state: staged,
      expectedConversationRoutes: []
    )

    let reused = try fixture.signedUpdateSet(
      revision: 8,
      materials: [
        LifecycleTestMaterial(purpose: .catalog, epoch: 2, streamRoute: nil, rawKeyByte: 0x42),
        LifecycleTestMaterial(
          purpose: .deviceCommandTx,
          epoch: 1,
          streamRoute: nil,
          rawKeyByte: 0x42
        ),
        LifecycleTestMaterial(
          purpose: .deviceReplyTx,
          epoch: 1,
          streamRoute: nil,
          rawKeyByte: 0x43
        ),
      ]
    )
    XCTAssertThrowsError(
      try fixture.setVerifier.prepareDurableStage(
        state: state,
        canonicalBytes: reused,
        expectedConversationRoutes: []
      )
    ) { error in
      XCTAssertEqual(error as? DeviceKeyLifecycleError, .secretReuse)
    }
  }

  func testBootstrapEpochZeroRebuildsFullRosterAndAdvancesIndependentSlots() throws {
    let bootstrap = try makeBootstrapEpochZeroFixture()
    var state = bootstrap.initialState

    for barrier in bootstrap.barriers {
      state = try bootstrap.crypto.setVerifier.prepareBootstrapEpochBarrier(
        state: state,
        barrier: barrier,
        expectedConversationRoutes: bootstrap.expectedConversationRoutes
      )
    }

    XCTAssertEqual(
      state.stateRevision,
      bootstrap.initialState.stateRevision + UInt64(bootstrap.barriers.count)
    )
    XCTAssertEqual(state.keyLifecycle?.slots.count, 5)
    XCTAssertEqual(
      state.keyLifecycle?.slot(purpose: .catalog, streamRoute: nil)?.current?.activationProof,
      bootstrap.barriers[0]
    )
    for (route, barrier) in zip(
      bootstrap.expectedConversationRoutes, bootstrap.barriers.dropFirst())
    {
      let slot = try XCTUnwrap(
        state.keyLifecycle?.slot(purpose: .conversationDEK, streamRoute: route)
      )
      XCTAssertEqual(slot.current?.activationProof, barrier)
      XCTAssertNil(slot.staged)
      XCTAssertTrue(slot.retired.isEmpty)
    }
    XCTAssertNil(
      state.keyLifecycle?.slot(purpose: .deviceCommandTx, streamRoute: nil)?.current?
        .activationProof
    )
    XCTAssertNil(
      state.keyLifecycle?.slot(purpose: .deviceReplyTx, streamRoute: nil)?.current?
        .activationProof
    )
    XCTAssertFalse(state.replayStates.contains { $0.scope.keyID.epoch == 0 })
    XCTAssertTrue(state.keyLifecycle?.slots.allSatisfy { $0.retired.isEmpty } == true)

    let basis = try state.auditingKeyLifecycleAcknowledgementBasis()
    XCTAssertEqual(basis.epochBarriers, bootstrap.barriers)
    XCTAssertNil(basis.directoryAdvance)
    _ = try bootstrap.crypto.setVerifier.auditColdOpen(
      state: state,
      expectedConversationRoutes: bootstrap.expectedConversationRoutes
    )

    XCTAssertThrowsError(
      try bootstrap.crypto.setVerifier.prepareBootstrapEpochBarrier(
        state: state,
        barrier: bootstrap.barriers[0],
        expectedConversationRoutes: bootstrap.expectedConversationRoutes
      )
    ) { error in
      XCTAssertEqual(error as? DeviceKeyLifecycleError, .invalidBarrier)
    }
  }

  func testBootstrapEpochZeroRejectsEveryRouteCursorSlotAndRevisionMismatch() throws {
    let bootstrap = try makeBootstrapEpochZeroFixture()
    let catalog = bootstrap.barriers[0]
    let mismatches = try [
      DeviceEpochBarrierV1(
        streamRoute: Data(repeating: 0xD1, count: 16),
        streamGeneration: catalog.streamGeneration,
        streamCursor: catalog.streamCursor,
        innerCursor: catalog.innerCursor,
        oldEpoch: 0,
        newEpoch: 1,
        keyDirectoryRevision: catalog.keyDirectoryRevision
      ),
      DeviceEpochBarrierV1(
        streamRoute: catalog.streamRoute,
        streamGeneration: Data(repeating: 0xD2, count: 16),
        streamCursor: catalog.streamCursor,
        innerCursor: catalog.innerCursor,
        oldEpoch: 0,
        newEpoch: 1,
        keyDirectoryRevision: catalog.keyDirectoryRevision
      ),
      DeviceEpochBarrierV1(
        streamRoute: catalog.streamRoute,
        streamGeneration: catalog.streamGeneration,
        streamCursor: .at(1),
        innerCursor: catalog.innerCursor,
        oldEpoch: 0,
        newEpoch: 1,
        keyDirectoryRevision: catalog.keyDirectoryRevision
      ),
      DeviceEpochBarrierV1(
        streamRoute: catalog.streamRoute,
        streamGeneration: catalog.streamGeneration,
        streamCursor: catalog.streamCursor,
        innerCursor: .catalog(.at(1)),
        oldEpoch: 0,
        newEpoch: 1,
        keyDirectoryRevision: catalog.keyDirectoryRevision
      ),
      DeviceEpochBarrierV1(
        streamRoute: catalog.streamRoute,
        streamGeneration: catalog.streamGeneration,
        streamCursor: catalog.streamCursor,
        innerCursor: .conversation(id: "wrong-slot", cursor: .beforeFirst),
        oldEpoch: 0,
        newEpoch: 1,
        keyDirectoryRevision: catalog.keyDirectoryRevision
      ),
      DeviceEpochBarrierV1(
        streamRoute: catalog.streamRoute,
        streamGeneration: catalog.streamGeneration,
        streamCursor: catalog.streamCursor,
        innerCursor: catalog.innerCursor,
        oldEpoch: 0,
        newEpoch: 1,
        keyDirectoryRevision: catalog.keyDirectoryRevision + 1
      ),
      DeviceEpochBarrierV1(
        streamRoute: catalog.streamRoute,
        streamGeneration: catalog.streamGeneration,
        streamCursor: catalog.streamCursor,
        innerCursor: catalog.innerCursor,
        oldEpoch: 1,
        newEpoch: 2,
        keyDirectoryRevision: catalog.keyDirectoryRevision
      ),
    ]

    for mismatch in mismatches {
      XCTAssertThrowsError(
        try bootstrap.crypto.setVerifier.prepareBootstrapEpochBarrier(
          state: bootstrap.initialState,
          barrier: mismatch,
          expectedConversationRoutes: bootstrap.expectedConversationRoutes
        )
      ) { error in
        XCTAssertEqual(error as? DeviceKeyLifecycleError, .invalidBarrier)
      }
    }
    XCTAssertThrowsError(
      try bootstrap.crypto.setVerifier.prepareBootstrapEpochBarrier(
        state: bootstrap.initialState,
        barrier: catalog,
        expectedConversationRoutes: [bootstrap.expectedConversationRoutes[0]]
      )
    ) { error in
      XCTAssertEqual(
        error as? DeviceKeyLifecycleError,
        .invalidRoster,
        "unexpected error: \(String(reflecting: error))"
      )
    }
  }

  func testStoredCarrierRejectsActivationProofForWrongPurposeRouteOrSource() throws {
    let bootstrap = try makeBootstrapEpochZeroFixture()
    let catalogBarrier = bootstrap.barriers[0]
    let conversationBarrier = bootstrap.barriers[1]
    let catalogEntry = try XCTUnwrap(
      bootstrap.initialState.keyDirectory.entries.first(where: {
        $0.keyID.purpose == .catalog
      })
    )
    let commandEntry = try XCTUnwrap(
      bootstrap.initialState.keyDirectory.entries.first(where: {
        $0.keyID.purpose == .deviceCommandTx
      })
    )

    XCTAssertThrowsError(
      try DeviceStoredKeyCarrierV1(
        keyID: commandEntry.keyID,
        streamRoute: commandEntry.streamRoute,
        keyDirectoryRevision: bootstrap.initialState.keyDirectory.revision,
        secretFingerprint: Data(repeating: 0xE1, count: 32),
        source: .bootstrapDirectory,
        activationProof: catalogBarrier
      )
    ) { error in
      XCTAssertEqual(error as? DeviceKeyLifecycleError, .invalidCarrier)
    }
    XCTAssertThrowsError(
      try DeviceStoredKeyCarrierV1(
        keyID: catalogEntry.keyID,
        streamRoute: catalogEntry.streamRoute,
        keyDirectoryRevision: bootstrap.initialState.keyDirectory.revision,
        secretFingerprint: Data(repeating: 0xE2, count: 32),
        source: .bootstrapDirectory,
        activationProof: conversationBarrier
      )
    ) { error in
      XCTAssertEqual(error as? DeviceKeyLifecycleError, .invalidCarrier)
    }

    let signedCatalog = try bootstrap.crypto.signedUpdate(
      purpose: .catalog,
      streamRoute: nil,
      rawKey: Data(repeating: 0x51, count: 32),
      // Keep every proof identity axis valid so rejection specifically proves
      // that a signed-update carrier cannot consume a bootstrap 0 -> 1 proof.
      epoch: 1,
      revision: bootstrap.initialState.keyDirectory.revision
    )
    XCTAssertThrowsError(
      try DeviceStoredKeyCarrierV1(
        keyID: signedCatalog.keyID,
        streamRoute: signedCatalog.streamRoute,
        keyDirectoryRevision: signedCatalog.keyDirectoryRevision,
        secretFingerprint: Data(repeating: 0xE3, count: 32),
        source: .signedUpdate(KeyUpdateCanonicalCodec.encode(signedCatalog)),
        activationProof: catalogBarrier
      )
    ) { error in
      XCTAssertEqual(error as? DeviceKeyLifecycleError, .invalidCarrier)
    }
  }

  func testExactBarrierActivatesOnlyItsSlotAndRetiredMaterialGCLeavesReuseTombstone()
    throws
  {
    let fixture = try KeyUpdateSetCryptoFixture()
    let conversationRoute = Data(repeating: 0x91, count: 16)
    let catalogStreamRoute = Data(repeating: 0x92, count: 16)
    let conversationID = "conversation-lifecycle"
    let bootstrapMaterials = lifecycleBootstrapMaterials(
      conversations: [
        LifecycleTestMaterial(
          purpose: .conversationDEK,
          epoch: 1,
          streamRoute: conversationRoute,
          rawKeyByte: 0x44
        )
      ]
    )
    let bootstrap = try fixture.signedDirectory(revision: 7, materials: bootstrapMaterials)
    let state = try lifecycleState(
      fixture: fixture,
      directory: bootstrap.directory,
      streamStates: [
        try DeviceStreamCursorStateV1(
          streamRoute: catalogStreamRoute,
          generation: Data(repeating: 0x93, count: 16),
          outerCursor: .at(40),
          innerCursor: .catalog(.at(39))
        ),
        try DeviceStreamCursorStateV1(
          streamRoute: conversationRoute,
          generation: Data(repeating: 0x94, count: 16),
          outerCursor: .at(50),
          innerCursor: .conversation(id: conversationID, cursor: .at(49))
        ),
      ]
    )
    let staged = try fixture.setVerifier.prepareDurableStage(
      state: state,
      canonicalBytes: fixture.signedUpdateSet(
        revision: 8,
        materials: [
          LifecycleTestMaterial(purpose: .catalog, epoch: 2, streamRoute: nil, rawKeyByte: 0x51),
          LifecycleTestMaterial(
            purpose: .conversationDEK,
            epoch: 2,
            streamRoute: conversationRoute,
            rawKeyByte: 0x52
          ),
          LifecycleTestMaterial(
            purpose: .deviceCommandTx,
            epoch: 1,
            streamRoute: nil,
            rawKeyByte: 0x42
          ),
          LifecycleTestMaterial(
            purpose: .deviceReplyTx,
            epoch: 1,
            streamRoute: nil,
            rawKeyByte: 0x43
          ),
        ]
      ),
      expectedConversationRoutes: [conversationRoute]
    )
    let barrier = try DeviceEpochBarrierV1(
      streamRoute: catalogStreamRoute,
      streamGeneration: Data(repeating: 0x93, count: 16),
      streamCursor: .at(40),
      innerCursor: .catalog(.at(39)),
      oldEpoch: 1,
      newEpoch: 2,
      keyDirectoryRevision: 8
    )
    let partiallyApplied = try staged.applyingEpochBarrier(
      barrier,
      activatedAtMS: 1_000
    )
    XCTAssertEqual(
      try partiallyApplied.applyingEpochBarrier(barrier, activatedAtMS: 2_000),
      partiallyApplied,
      "exact duplicate barrier must be idempotent after its cursor advanced"
    )

    XCTAssertEqual(
      partiallyApplied.keyLifecycle?.slot(purpose: .catalog, streamRoute: nil)?.current?.keyID
        .epoch,
      2
    )
    XCTAssertNil(
      partiallyApplied.keyLifecycle?.slot(purpose: .catalog, streamRoute: nil)?.staged
    )
    XCTAssertEqual(
      partiallyApplied.keyLifecycle?
        .slot(purpose: .conversationDEK, streamRoute: conversationRoute)?.staged?.keyID.epoch,
      2
    )
    XCTAssertEqual(partiallyApplied.senderCounter.keyDirectoryRevision, 7)
    XCTAssertEqual(
      partiallyApplied.streamStates.first(where: { $0.streamRoute == catalogStreamRoute })?
        .outerCursor,
      .at(41)
    )

    let deadline = 1_000 + ReplayWindow.retiredWindowRetentionMilliseconds
    let retainedInventory = try fixture.setVerifier.auditColdOpen(
      state: partiallyApplied,
      expectedConversationRoutes: [conversationRoute]
    )
    let currentCatalog = try retainedInventory.resolveReceivingKey(
      keyID: KeyIDV1(purpose: .catalog, epoch: 2),
      keyDirectoryRevision: 8,
      streamRoute: catalogStreamRoute,
      nowMS: deadline - 1
    )
    XCTAssertEqual(currentCatalog.lifecycle, .activatedPending)
    let stagedConversation = try retainedInventory.resolveReceivingKey(
      keyID: KeyIDV1(purpose: .conversationDEK, epoch: 2),
      keyDirectoryRevision: 8,
      streamRoute: conversationRoute,
      nowMS: deadline - 1
    )
    XCTAssertEqual(stagedConversation.lifecycle, .staged)
    let retiredCatalog = try retainedInventory.resolveReceivingKey(
      keyID: KeyIDV1(purpose: .catalog, epoch: 1),
      keyDirectoryRevision: 7,
      streamRoute: catalogStreamRoute,
      nowMS: deadline - 1
    )
    XCTAssertEqual(
      retiredCatalog.lifecycle,
      .retired(retiredAtMS: 1_000, deleteAfterMS: deadline)
    )
    let delayedContext = OuterContextV1(
      frameKind: .catalogPublish,
      relayProtocolVersion: relayProtocolVersionV2,
      e2eeFormatVersion: 1,
      machineRoute: fixture.machineRoute,
      deviceRoute: nil,
      streamRoute: catalogStreamRoute,
      requestRoute: nil,
      streamGeneration: Data(repeating: 0x93, count: 16),
      streamCursor: .at(40),
      streamSeq: 41,
      messageKeyEpoch: 1
    )
    let delayedSendingKey = try AeadSendingKey(
      keyID: KeyIDV1(purpose: .catalog, epoch: 1),
      epoch: 1,
      keyDirectoryRevision: 7,
      payloadKind: .catalogDelta,
      rawKey: Data(repeating: 0x41, count: 32)
    )
    let delayedUnsigned = try RelayCrypto.sealSymmetric(
      Data("delayed-catalog".utf8),
      key: delayedSendingKey,
      context: delayedContext,
      counter: 17
    )
    let delayedSigned = try RelayCrypto.signSealed(
      delayedUnsigned,
      key: fixture.dataSigningKey,
      context: delayedContext
    )
    let delayedWire = try RelayV2SignedSealedBlobCodec.encode(
      delayedSigned,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
    let delayedVerifier = try MachineDataVerifier(
      machineRoute: fixture.machineRoute,
      deviceRoute: fixture.deviceRoute,
      verifiedCertificate: VerifiedMachineDataCertificate(
        certificate: RelayV2SignedCertificate(
          subjectPubkey: fixture.dataSigningKey.publicKey.rawRepresentation,
          certRole: .data,
          generation: 4,
          rootKeyId: fixture.rootKeyID,
          trustEpoch: 3,
          notAfterMs: nil,
          signature: Data(repeating: 0xD4, count: 64)
        ),
        signingKey: fixture.dataSigningKey.publicKey
      ),
      currentKeyDirectoryRevision: retainedInventory.activeRevision,
      maximumKeySyncAdvance: 1
    )
    let delayedCandidate = try delayedVerifier.verifyRetiredMachineData(
      wireBytes: delayedWire,
      context: delayedContext,
      capability: retiredCatalog
    )
    XCTAssertEqual(delayedCandidate.replayScope.keyID, delayedSendingKey.keyID)
    XCTAssertEqual(delayedCandidate.keyDirectoryRevision, 7)
    XCTAssertEqual(delayedCandidate.counter, 17)
    var wrongDelayedRoute = delayedContext
    wrongDelayedRoute.streamRoute = Data(repeating: 0x95, count: 16)
    XCTAssertThrowsError(
      try delayedVerifier.verifyRetiredMachineData(
        wireBytes: delayedWire,
        context: wrongDelayedRoute,
        capability: retiredCatalog
      )
    )
    XCTAssertThrowsError(
      try retainedInventory.resolveReceivingKey(
        keyID: KeyIDV1(purpose: .catalog, epoch: 1),
        keyDirectoryRevision: 8,
        streamRoute: catalogStreamRoute,
        nowMS: deadline - 1
      )
    ) { error in
      XCTAssertEqual(error as? DeviceKeyLifecycleError, .receivingKeyNotFound)
    }
    XCTAssertThrowsError(
      try retainedInventory.resolveReceivingKey(
        keyID: KeyIDV1(purpose: .catalog, epoch: 1),
        keyDirectoryRevision: 7,
        streamRoute: catalogStreamRoute,
        nowMS: deadline
      )
    ) { error in
      XCTAssertEqual(error as? DeviceKeyLifecycleError, .retiredKeyExpired)
    }
    XCTAssertEqual(
      try partiallyApplied.garbageCollectingRetiredKeys(nowMS: deadline - 1),
      partiallyApplied
    )
    let collected = try partiallyApplied.garbageCollectingRetiredKeys(nowMS: deadline)
    XCTAssertTrue(
      collected.keyLifecycle?.slot(purpose: .catalog, streamRoute: nil)?.retired.isEmpty == true
    )
    XCTAssertEqual(collected.keyLifecycle?.retiredSecretFingerprints.count, 1)
    let collectedInventory = try fixture.setVerifier.auditColdOpen(
      state: collected,
      expectedConversationRoutes: [conversationRoute]
    )
    XCTAssertThrowsError(
      try collectedInventory.resolveReceivingKey(
        keyID: KeyIDV1(purpose: .catalog, epoch: 1),
        keyDirectoryRevision: 7,
        streamRoute: catalogStreamRoute,
        nowMS: deadline + 1
      )
    ) { error in
      XCTAssertEqual(error as? DeviceKeyLifecycleError, .receivingKeyNotFound)
    }
  }

  func testDirectoryRevisionAdvanceActivatesNewConversationWithoutSyntheticBarrier() throws {
    let fixture = try KeyUpdateSetCryptoFixture()
    let catalogStreamRoute = Data(repeating: 0xA1, count: 16)
    let newConversationRoute = Data(repeating: 0xA2, count: 16)
    let bootstrap = try fixture.signedDirectory(
      revision: 7,
      materials: lifecycleBootstrapMaterials()
    )
    let state = try lifecycleState(
      fixture: fixture,
      directory: bootstrap.directory,
      streamStates: [
        try DeviceStreamCursorStateV1(
          streamRoute: catalogStreamRoute,
          generation: Data(repeating: 0xA3, count: 16),
          outerCursor: .at(70),
          innerCursor: .catalog(.at(69))
        )
      ]
    )
    let staged = try fixture.setVerifier.prepareDurableStage(
      state: state,
      canonicalBytes: fixture.signedUpdateSet(
        revision: 8,
        materials: [
          LifecycleTestMaterial(purpose: .catalog, epoch: 1, streamRoute: nil, rawKeyByte: 0x41),
          LifecycleTestMaterial(
            purpose: .conversationDEK,
            epoch: 1,
            streamRoute: newConversationRoute,
            rawKeyByte: 0x61
          ),
          LifecycleTestMaterial(
            purpose: .deviceCommandTx,
            epoch: 1,
            streamRoute: nil,
            rawKeyByte: 0x42
          ),
          LifecycleTestMaterial(
            purpose: .deviceReplyTx,
            epoch: 1,
            streamRoute: nil,
            rawKeyByte: 0x43
          ),
        ]
      ),
      expectedConversationRoutes: [newConversationRoute]
    )
    let advance = try DeviceDirectoryRevisionAdvanceV1(
      streamRoute: catalogStreamRoute,
      streamGeneration: Data(repeating: 0xA3, count: 16),
      streamSequence: 71,
      fromRevision: 7,
      toRevision: 8
    )
    let activated = try staged.applyingDirectoryRevisionAdvance(advance)

    XCTAssertEqual(activated.senderCounter.keyDirectoryRevision, 8)
    XCTAssertNil(activated.keyLifecycle?.stagedTransition)
    XCTAssertEqual(
      activated.keyLifecycle?
        .slot(purpose: .conversationDEK, streamRoute: newConversationRoute)?.current?.keyID.epoch,
      1
    )
    XCTAssertEqual(
      activated.replayStates.first(where: {
        $0.scope.streamRoute == newConversationRoute
      })?.status,
      .active
    )
  }

  func testActivatedPendingAllowsNextRevisionDataAndProofAliasSurvivesCatalogRebind()
    async throws
  {
    let fixture = try KeyUpdateSetCryptoFixture()
    let oldRoute = Data(repeating: 0xB1, count: 16)
    let oldGeneration = Data(repeating: 0xB2, count: 16)
    let newRoute = Data(repeating: 0xB3, count: 16)
    let newGeneration = Data(repeating: 0xB4, count: 16)
    let conversationRoute = Data(repeating: 0xB5, count: 16)
    let bootstrap = try fixture.signedDirectory(
      revision: 7,
      materials: lifecycleBootstrapMaterials(
        conversations: [
          LifecycleTestMaterial(
            purpose: .conversationDEK,
            epoch: 1,
            streamRoute: conversationRoute,
            rawKeyByte: 0x44
          )
        ])
    )
    let baseline = try lifecycleState(
      fixture: fixture,
      directory: bootstrap.directory,
      streamStates: [
        try DeviceStreamCursorStateV1(
          streamRoute: oldRoute,
          generation: oldGeneration,
          outerCursor: .at(10),
          innerCursor: .catalog(.at(9))
        ),
        try DeviceStreamCursorStateV1(
          streamRoute: conversationRoute,
          generation: Data(repeating: 0xB6, count: 16),
          outerCursor: .at(20),
          innerCursor: .conversation(id: "pending-capability", cursor: .at(19))
        ),
      ]
    )
    let staged = try fixture.setVerifier.prepareDurableStage(
      state: baseline,
      canonicalBytes: fixture.signedUpdateSet(
        revision: 8,
        materials: [
          LifecycleTestMaterial(purpose: .catalog, epoch: 2, streamRoute: nil, rawKeyByte: 0x51),
          LifecycleTestMaterial(
            purpose: .conversationDEK,
            epoch: 2,
            streamRoute: conversationRoute,
            rawKeyByte: 0x52
          ),
          LifecycleTestMaterial(
            purpose: .deviceCommandTx,
            epoch: 1,
            streamRoute: nil,
            rawKeyByte: 0x42
          ),
          LifecycleTestMaterial(
            purpose: .deviceReplyTx,
            epoch: 1,
            streamRoute: nil,
            rawKeyByte: 0x43
          ),
        ]
      ),
      expectedConversationRoutes: [conversationRoute]
    )
    let episode = try lifecycleKeySyncEpisode(
      targetRevision: 8,
      observedKeyID: KeyIDV1(purpose: .catalog, epoch: 2)
    )
    let stagedWithEpisode = try copiedLifecycleState(
      staged,
      stateRevision: 1,
      streamStates: staged.streamStates,
      keySyncEpisode: episode
    )
    let barrier = try DeviceEpochBarrierV1(
      streamRoute: oldRoute,
      streamGeneration: oldGeneration,
      streamCursor: .at(10),
      innerCursor: .catalog(.at(9)),
      oldEpoch: 1,
      newEpoch: 2,
      keyDirectoryRevision: 8
    )
    let barrierFrame = try lifecyclePublicationFrame(
      fixture: fixture,
      streamRoute: oldRoute,
      streamGeneration: oldGeneration,
      streamSequence: barrier.appliedStreamSequence,
      headerRevision: 8,
      keyID: KeyIDV1(purpose: .catalog, epoch: 2),
      rawKeyByte: 0x51,
      payloadKind: .keyUpdate,
      payload: DaemonKeyControlCanonicalCodec.encode(.epochBarrier(barrier)),
      counter: 2
    )
    let currentVerifier = try lifecycleMachineDataVerifier(
      fixture: fixture,
      currentRevision: 7
    )
    let stagedInventory = try fixture.setVerifier.auditColdOpen(
      state: stagedWithEpisode,
      expectedConversationRoutes: [conversationRoute]
    )
    let stagedCapability = try stagedInventory.resolveReceivingKey(
      keyID: KeyIDV1(purpose: .catalog, epoch: 2),
      keyDirectoryRevision: 8,
      streamRoute: oldRoute,
      nowMS: LifecycleReplayEnvironment.clockMS
    )
    let stagedCandidate = try currentVerifier.verifyStagedKeyControl(
      wireBytes: barrierFrame.wire,
      context: barrierFrame.context,
      capability: stagedCapability
    )

    let activationEnvironment = try LifecycleReplayEnvironment(state: stagedWithEpisode)
    defer { activationEnvironment.removeSandbox() }
    let activationCoordinator = try await activationEnvironment.start()
    let freshBarrier = try await activationCoordinator.admitReplay(
      scope: stagedCandidate.replayScope,
      counter: stagedCandidate.counter,
      ciphertextHash: stagedCandidate.ciphertextHash,
      observedAtMS: LifecycleReplayEnvironment.clockMS
    )
    guard
      case .epochBarrier(let openedBarrier) = try currentVerifier.openStagedKeyControl(
        stagedCandidate,
        replayAdmission: freshBarrier
      )
    else {
      return XCTFail("staged barrier should open before partial activation")
    }
    let activated = try await activationCoordinator.applyEpochBarrier(
      expected: freshBarrier.snapshot,
      barrier: openedBarrier
    )
    let duplicateBarrier = try await activationCoordinator.admitReplay(
      scope: stagedCandidate.replayScope,
      counter: stagedCandidate.counter,
      ciphertextHash: stagedCandidate.ciphertextHash,
      observedAtMS: LifecycleReplayEnvironment.clockMS + 1
    )
    XCTAssertEqual(duplicateBarrier.disposition, .exactDuplicate)
    let activatedInventory = try fixture.setVerifier.auditColdOpen(
      state: duplicateBarrier.snapshot.state,
      expectedConversationRoutes: [conversationRoute]
    )
    let activatedCapability = try activatedInventory.resolveReceivingKey(
      keyID: KeyIDV1(purpose: .catalog, epoch: 2),
      keyDirectoryRevision: 8,
      streamRoute: oldRoute,
      nowMS: LifecycleReplayEnvironment.clockMS
    )
    XCTAssertEqual(activatedCapability.lifecycle, .activatedPending)
    let activatedDuplicate = try currentVerifier.verifyActivatedPendingMachineData(
      wireBytes: barrierFrame.wire,
      context: barrierFrame.context,
      capability: activatedCapability
    )
    guard
      case .epochBarrierDuplicate(let recoveredBarrier) =
        try currentVerifier.openActivatedPendingMachineData(
          activatedDuplicate,
          replayAdmission: duplicateBarrier
        )
    else {
      return XCTFail("activated-pending must recover its exact barrier duplicate")
    }
    XCTAssertEqual(recoveredBarrier, barrier)

    let reboundState = try copiedLifecycleState(
      activated.snapshot.state,
      stateRevision: 1,
      streamStates: [
        try DeviceStreamCursorStateV1(
          streamRoute: newRoute,
          generation: newGeneration,
          outerCursor: .at(barrier.appliedStreamSequence),
          innerCursor: .catalog(.at(9))
        ),
        try XCTUnwrap(
          activated.snapshot.state.streamStates.first(where: {
            $0.streamRoute == conversationRoute
          })),
      ],
      keySyncEpisode: activated.snapshot.state.keySyncEpisode
    )
    let reboundInventory = try fixture.setVerifier.auditColdOpen(
      state: reboundState,
      expectedConversationRoutes: [conversationRoute]
    )
    let liveCapability = try reboundInventory.resolveReceivingKey(
      keyID: KeyIDV1(purpose: .catalog, epoch: 2),
      keyDirectoryRevision: 8,
      streamRoute: newRoute,
      nowMS: LifecycleReplayEnvironment.clockMS
    )
    let proofAlias = try reboundInventory.resolveReceivingKey(
      keyID: KeyIDV1(purpose: .catalog, epoch: 2),
      keyDirectoryRevision: 8,
      streamRoute: oldRoute,
      nowMS: LifecycleReplayEnvironment.clockMS
    )
    XCTAssertEqual(liveCapability.lifecycle, .activatedPending)
    XCTAssertEqual(proofAlias.lifecycle, .epochBarrierProofAlias)

    let reboundEnvironment = try LifecycleReplayEnvironment(state: reboundState)
    defer { reboundEnvironment.removeSandbox() }
    let reboundCoordinator = try await reboundEnvironment.start()
    let aliasCandidate = try currentVerifier.verifyEpochBarrierProofAlias(
      wireBytes: barrierFrame.wire,
      context: barrierFrame.context,
      capability: proofAlias
    )
    let aliasAdmission = try await reboundCoordinator.admitReplay(
      scope: aliasCandidate.replayScope,
      counter: aliasCandidate.counter,
      ciphertextHash: aliasCandidate.ciphertextHash,
      observedAtMS: LifecycleReplayEnvironment.clockMS + 2
    )
    XCTAssertEqual(
      try currentVerifier.openEpochBarrierProofAlias(
        aliasCandidate,
        replayAdmission: aliasAdmission
      ),
      barrier
    )

    let ordinaryPayload = Data("next-revision-catalog".utf8)
    let ordinaryFrame = try lifecyclePublicationFrame(
      fixture: fixture,
      streamRoute: newRoute,
      streamGeneration: newGeneration,
      streamSequence: barrier.appliedStreamSequence + 1,
      headerRevision: 8,
      keyID: KeyIDV1(purpose: .catalog, epoch: 2),
      rawKeyByte: 0x51,
      payloadKind: .catalogDelta,
      payload: ordinaryPayload,
      counter: 3
    )
    let ordinaryCandidate = try currentVerifier.verifyActivatedPendingMachineData(
      wireBytes: ordinaryFrame.wire,
      context: ordinaryFrame.context,
      capability: liveCapability
    )
    let ordinaryAdmission = try await reboundCoordinator.admitReplay(
      scope: ordinaryCandidate.replayScope,
      counter: ordinaryCandidate.counter,
      ciphertextHash: ordinaryCandidate.ciphertextHash,
      observedAtMS: LifecycleReplayEnvironment.clockMS + 3
    )
    guard
      case .data(let openedData) = try currentVerifier.openActivatedPendingMachineData(
        ordinaryCandidate,
        replayAdmission: ordinaryAdmission
      )
    else {
      return XCTFail("activated-pending ordinary data should remain deliverable")
    }
    XCTAssertEqual(openedData.payloadKind, .catalogDelta)
    XCTAssertEqual(openedData.payload, ordinaryPayload)

    let misplacedControl = try lifecyclePublicationFrame(
      fixture: fixture,
      streamRoute: newRoute,
      streamGeneration: newGeneration,
      streamSequence: barrier.appliedStreamSequence + 2,
      headerRevision: 8,
      keyID: KeyIDV1(purpose: .catalog, epoch: 2),
      rawKeyByte: 0x51,
      payloadKind: .keyUpdate,
      payload: DaemonKeyControlCanonicalCodec.encode(.epochBarrier(barrier)),
      counter: 4
    )
    let misplacedCandidate = try currentVerifier.verifyActivatedPendingMachineData(
      wireBytes: misplacedControl.wire,
      context: misplacedControl.context,
      capability: liveCapability
    )
    let misplacedFresh = try await reboundCoordinator.admitReplay(
      scope: misplacedCandidate.replayScope,
      counter: misplacedCandidate.counter,
      ciphertextHash: misplacedCandidate.ciphertextHash,
      observedAtMS: LifecycleReplayEnvironment.clockMS + 4
    )
    XCTAssertThrowsError(
      try currentVerifier.openActivatedPendingMachineData(
        misplacedCandidate,
        replayAdmission: misplacedFresh
      )
    ) { error in
      XCTAssertEqual(error as? MachineDataVerifierError, .activationProofMismatch)
    }
    let misplacedDuplicate = try await reboundCoordinator.admitReplay(
      scope: misplacedCandidate.replayScope,
      counter: misplacedCandidate.counter,
      ciphertextHash: misplacedCandidate.ciphertextHash,
      observedAtMS: LifecycleReplayEnvironment.clockMS + 5
    )
    XCTAssertThrowsError(
      try currentVerifier.openActivatedPendingMachineData(
        misplacedCandidate,
        replayAdmission: misplacedDuplicate
      )
    ) { error in
      XCTAssertEqual(error as? MachineDataVerifierError, .activationProofMismatch)
    }

    let oldRouteData = try lifecyclePublicationFrame(
      fixture: fixture,
      streamRoute: oldRoute,
      streamGeneration: oldGeneration,
      streamSequence: barrier.appliedStreamSequence,
      headerRevision: 8,
      keyID: KeyIDV1(purpose: .catalog, epoch: 2),
      rawKeyByte: 0x51,
      payloadKind: .catalogDelta,
      payload: Data("must-not-reopen-old-route".utf8),
      counter: 5
    )
    let oldRouteCandidate = try currentVerifier.verifyEpochBarrierProofAlias(
      wireBytes: oldRouteData.wire,
      context: oldRouteData.context,
      capability: proofAlias
    )
    let oldRouteFresh = try await reboundCoordinator.admitReplay(
      scope: oldRouteCandidate.replayScope,
      counter: oldRouteCandidate.counter,
      ciphertextHash: oldRouteCandidate.ciphertextHash,
      observedAtMS: LifecycleReplayEnvironment.clockMS + 6
    )
    XCTAssertThrowsError(
      try currentVerifier.openEpochBarrierProofAlias(
        oldRouteCandidate,
        replayAdmission: oldRouteFresh
      )
    ) { error in
      XCTAssertEqual(
        error as? MachineDataVerifierError,
        .activatedPendingReplayAdmissionRequired
      )
    }
  }

  func testDirectoryAdvancePredecessorOnlyOpensExactDurableProofDuplicate() async throws {
    let fixture = try KeyUpdateSetCryptoFixture()
    let catalogRoute = Data(repeating: 0xC1, count: 16)
    let catalogGeneration = Data(repeating: 0xC2, count: 16)
    let newConversationRoute = Data(repeating: 0xC3, count: 16)
    let bootstrap = try fixture.signedDirectory(
      revision: 7,
      materials: lifecycleBootstrapMaterials()
    )
    let baseline = try lifecycleState(
      fixture: fixture,
      directory: bootstrap.directory,
      streamStates: [
        try DeviceStreamCursorStateV1(
          streamRoute: catalogRoute,
          generation: catalogGeneration,
          outerCursor: .at(30),
          innerCursor: .catalog(.at(29))
        )
      ]
    )
    let staged = try fixture.setVerifier.prepareDurableStage(
      state: baseline,
      canonicalBytes: fixture.signedUpdateSet(
        revision: 8,
        materials: [
          LifecycleTestMaterial(purpose: .catalog, epoch: 1, streamRoute: nil, rawKeyByte: 0x41),
          LifecycleTestMaterial(
            purpose: .conversationDEK,
            epoch: 1,
            streamRoute: newConversationRoute,
            rawKeyByte: 0x61
          ),
          LifecycleTestMaterial(
            purpose: .deviceCommandTx,
            epoch: 1,
            streamRoute: nil,
            rawKeyByte: 0x42
          ),
          LifecycleTestMaterial(
            purpose: .deviceReplyTx,
            epoch: 1,
            streamRoute: nil,
            rawKeyByte: 0x43
          ),
        ]
      ),
      expectedConversationRoutes: [newConversationRoute]
    )
    let episode = try lifecycleKeySyncEpisode(
      targetRevision: 8,
      observedKeyID: KeyIDV1(purpose: .catalog, epoch: 1)
    )
    let stagedWithEpisode = try copiedLifecycleState(
      staged,
      stateRevision: 1,
      streamStates: staged.streamStates,
      keySyncEpisode: episode
    )
    let proof = try DeviceDirectoryRevisionAdvanceV1(
      streamRoute: catalogRoute,
      streamGeneration: catalogGeneration,
      streamSequence: 31,
      fromRevision: 7,
      toRevision: 8
    )
    let frame = try lifecyclePublicationFrame(
      fixture: fixture,
      streamRoute: catalogRoute,
      streamGeneration: catalogGeneration,
      streamSequence: proof.streamSequence,
      headerRevision: 7,
      keyID: KeyIDV1(purpose: .catalog, epoch: 1),
      rawKeyByte: 0x41,
      payloadKind: .keyUpdate,
      payload: DaemonKeyControlCanonicalCodec.encode(
        .directoryRevisionAdvance(
          try DaemonDirectoryRevisionAdvanceV1(fromRevision: 7, toRevision: 8)
        )),
      counter: 4
    )
    let oldVerifier = try lifecycleMachineDataVerifier(
      fixture: fixture,
      currentRevision: 7
    )
    let stagedInventory = try fixture.setVerifier.auditColdOpen(
      state: stagedWithEpisode,
      expectedConversationRoutes: [newConversationRoute]
    )
    let stagedCatalog = try stagedInventory.resolveReceivingKey(
      keyID: KeyIDV1(purpose: .catalog, epoch: 1),
      keyDirectoryRevision: 8,
      streamRoute: catalogRoute,
      nowMS: LifecycleReplayEnvironment.clockMS
    )
    let stagedCandidate = try oldVerifier.verifyStagedKeyControl(
      wireBytes: frame.wire,
      context: frame.context,
      capability: stagedCatalog
    )
    let environment = try LifecycleReplayEnvironment(state: stagedWithEpisode)
    defer { environment.removeSandbox() }
    let coordinator = try await environment.start()
    let fresh = try await coordinator.admitReplay(
      scope: stagedCandidate.replayScope,
      counter: stagedCandidate.counter,
      ciphertextHash: stagedCandidate.ciphertextHash,
      observedAtMS: LifecycleReplayEnvironment.clockMS
    )
    guard
      case .directoryRevisionAdvance(let openedProof) = try oldVerifier.openStagedKeyControl(
        stagedCandidate,
        replayAdmission: fresh
      )
    else {
      return XCTFail("staged directory proof should open")
    }
    XCTAssertEqual(openedProof, proof)
    let activated = try await coordinator.applyDirectoryRevisionAdvance(
      expected: fresh.snapshot,
      advance: openedProof
    )
    let inventory = try fixture.setVerifier.auditColdOpen(
      state: activated.state,
      expectedConversationRoutes: [newConversationRoute]
    )
    let predecessor = try inventory.resolveReceivingKey(
      keyID: KeyIDV1(purpose: .catalog, epoch: 1),
      keyDirectoryRevision: 7,
      streamRoute: catalogRoute,
      nowMS: LifecycleReplayEnvironment.clockMS
    )
    XCTAssertEqual(predecessor.lifecycle, .directoryAdvancePredecessor)
    let currentVerifier = try lifecycleMachineDataVerifier(
      fixture: fixture,
      currentRevision: 8
    )
    let predecessorCandidate = try currentVerifier.verifyDirectoryAdvancePredecessor(
      wireBytes: frame.wire,
      context: frame.context,
      capability: predecessor
    )
    let duplicate = try await coordinator.admitReplay(
      scope: predecessorCandidate.replayScope,
      counter: predecessorCandidate.counter,
      ciphertextHash: predecessorCandidate.ciphertextHash,
      observedAtMS: LifecycleReplayEnvironment.clockMS + 1
    )
    XCTAssertEqual(duplicate.disposition, .exactDuplicate)
    XCTAssertEqual(
      try currentVerifier.openDirectoryAdvancePredecessor(
        predecessorCandidate,
        replayAdmission: duplicate
      ),
      proof
    )

    var wrongGeneration = frame.context
    wrongGeneration.streamGeneration = Data(repeating: 0xCF, count: 16)
    XCTAssertThrowsError(
      try currentVerifier.verifyDirectoryAdvancePredecessor(
        wireBytes: frame.wire,
        context: wrongGeneration,
        capability: predecessor
      )
    ) { error in
      XCTAssertEqual(error as? MachineDataVerifierError, .directoryAdvanceProofMismatch)
    }

    let rollbackData = try lifecyclePublicationFrame(
      fixture: fixture,
      streamRoute: catalogRoute,
      streamGeneration: catalogGeneration,
      streamSequence: proof.streamSequence,
      headerRevision: 7,
      keyID: KeyIDV1(purpose: .catalog, epoch: 1),
      rawKeyByte: 0x41,
      payloadKind: .catalogDelta,
      payload: Data("must-not-generalize-predecessor".utf8),
      counter: 5
    )
    let rollbackCandidate = try currentVerifier.verifyDirectoryAdvancePredecessor(
      wireBytes: rollbackData.wire,
      context: rollbackData.context,
      capability: predecessor
    )
    let rollbackFresh = try await coordinator.admitReplay(
      scope: rollbackCandidate.replayScope,
      counter: rollbackCandidate.counter,
      ciphertextHash: rollbackCandidate.ciphertextHash,
      observedAtMS: LifecycleReplayEnvironment.clockMS + 2
    )
    XCTAssertThrowsError(
      try currentVerifier.openDirectoryAdvancePredecessor(
        rollbackCandidate,
        replayAdmission: rollbackFresh
      )
    ) { error in
      XCTAssertEqual(
        error as? MachineDataVerifierError,
        .directoryAdvanceReplayAdmissionRequired
      )
    }
    let rollbackDuplicate = try await coordinator.admitReplay(
      scope: rollbackCandidate.replayScope,
      counter: rollbackCandidate.counter,
      ciphertextHash: rollbackCandidate.ciphertextHash,
      observedAtMS: LifecycleReplayEnvironment.clockMS + 3
    )
    XCTAssertThrowsError(
      try currentVerifier.openDirectoryAdvancePredecessor(
        rollbackCandidate,
        replayAdmission: rollbackDuplicate
      )
    ) { error in
      XCTAssertEqual(error as? MachineDataVerifierError, .directoryAdvanceProofMismatch)
    }
  }

  func testExactNextKeySyncReplyRequiresAuditedReplyKeyRouteSignatureAndUpdateSet() throws {
    let fixture = try KeyUpdateSetCryptoFixture()
    let bootstrap = try fixture.signedDirectory(
      revision: 7,
      materials: lifecycleBootstrapMaterials()
    )
    let state = try lifecycleState(fixture: fixture, directory: bootstrap.directory)
    let inventory = try fixture.setVerifier.auditColdOpen(
      state: state,
      expectedConversationRoutes: []
    )
    let requestRoute = Data(repeating: 0xD1, count: 16)
    let capability = try inventory.exactNextKeySyncReplyCapability(
      requestRoute: requestRoute
    )
    let verifier = try MachineDataVerifier(
      machineRoute: fixture.machineRoute,
      deviceRoute: fixture.deviceRoute,
      verifiedCertificate: VerifiedMachineDataCertificate(
        certificate: RelayV2SignedCertificate(
          subjectPubkey: fixture.dataSigningKey.publicKey.rawRepresentation,
          certRole: .data,
          generation: 4,
          rootKeyId: fixture.rootKeyID,
          trustEpoch: 3,
          notAfterMs: nil,
          signature: Data(repeating: 0xD2, count: 64)
        ),
        signingKey: fixture.dataSigningKey.publicKey
      ),
      currentKeyDirectoryRevision: 7,
      maximumKeySyncAdvance: 4
    )
    let nextSetBytes = try fixture.signedUpdateSet(
      revision: 8,
      materials: [
        LifecycleTestMaterial(
          purpose: .catalog,
          epoch: 2,
          streamRoute: nil,
          rawKeyByte: 0x51
        )
      ]
    )
    let nextSet = try KeyUpdateSetCanonicalCodec.decode(nextSetBytes)
    let control = try DaemonKeyControlCanonicalCodec.encode(.updateSet(nextSet))
    let success = try keySyncReplyFrame(
      fixture: fixture,
      requestRoute: requestRoute,
      headerRevision: 8,
      keyID: KeyIDV1(purpose: .deviceReplyTx, epoch: 1),
      rawKeyByte: 0x43,
      controlBytes: control
    )

    let candidate = try verifier.verifyExactNextKeySyncReply(
      wireBytes: success.wire,
      context: success.context,
      capability: capability
    )
    XCTAssertEqual(candidate.keyDirectoryRevision, 8)
    XCTAssertEqual(candidate.replayScope.keyID.purpose, .deviceReplyTx)
    XCTAssertNil(candidate.replayScope.streamRoute)
    let opened = try verifier.openExactNextKeySyncReply(candidate)
    XCTAssertEqual(opened.keyDirectoryRevision, 8)
    XCTAssertEqual(opened.canonicalBytes, nextSetBytes)

    var wrongRoute = success.context
    wrongRoute.requestRoute = Data(repeating: 0xD3, count: 16)
    XCTAssertThrowsError(
      try verifier.verifyExactNextKeySyncReply(
        wireBytes: success.wire,
        context: wrongRoute,
        capability: capability
      )
    ) { error in
      XCTAssertEqual(error as? MachineDataVerifierError, .invalidRequestRoute)
    }

    let skippedSetBytes = try fixture.signedUpdateSet(
      revision: 9,
      materials: [
        LifecycleTestMaterial(
          purpose: .catalog,
          epoch: 2,
          streamRoute: nil,
          rawKeyByte: 0x51
        )
      ]
    )
    let skipped = try keySyncReplyFrame(
      fixture: fixture,
      requestRoute: requestRoute,
      headerRevision: 9,
      keyID: KeyIDV1(purpose: .deviceReplyTx, epoch: 1),
      rawKeyByte: 0x43,
      controlBytes: DaemonKeyControlCanonicalCodec.encode(
        .updateSet(try KeyUpdateSetCanonicalCodec.decode(skippedSetBytes))
      )
    )
    XCTAssertThrowsError(
      try verifier.verifyExactNextKeySyncReply(
        wireBytes: skipped.wire,
        context: skipped.context,
        capability: capability
      )
    ) { error in
      XCTAssertEqual(error as? MachineDataVerifierError, .exactNextRevisionRequired)
    }

    var wrongFamily = success.context
    wrongFamily.frameKind = .conversationPublish
    XCTAssertThrowsError(
      try verifier.verifyExactNextKeySyncReply(
        wireBytes: success.wire,
        context: wrongFamily,
        capability: capability
      )
    )

    let wrongKey = try keySyncReplyFrame(
      fixture: fixture,
      requestRoute: requestRoute,
      headerRevision: 8,
      keyID: KeyIDV1(purpose: .catalog, epoch: 1),
      rawKeyByte: 0x41,
      controlBytes: control
    )
    XCTAssertThrowsError(
      try verifier.verifyExactNextKeySyncReply(
        wireBytes: wrongKey.wire,
        context: wrongKey.context,
        capability: capability
      )
    )

    var forged = success.wire
    forged[forged.count - 1] ^= 1
    XCTAssertThrowsError(
      try verifier.verifyExactNextKeySyncReply(
        wireBytes: forged,
        context: success.context,
        capability: capability
      )
    ) { error in
      XCTAssertEqual(error as? RelayCryptoError, .badSignature)
    }

    let authority = try DeviceKeyControlAuthorityV1(
      machineRoute: fixture.machineRoute,
      deviceRoute: fixture.deviceRoute,
      grantSerial: 9,
      rootTrustEpoch: 3
    )
    let wrongVariant = try keySyncReplyFrame(
      fixture: fixture,
      requestRoute: requestRoute,
      headerRevision: 8,
      keyID: KeyIDV1(purpose: .deviceReplyTx, epoch: 1),
      rawKeyByte: 0x43,
      controlBytes: DaemonKeyControlCanonicalCodec.encode(
        .directoryCurrent(
          try DaemonDirectoryCurrentV1(
            authority: authority,
            currentKeyDirectoryRevision: 7,
            requestedKeyDirectoryRevision: 8
          ))
      )
    )
    let wrongVariantCandidate = try verifier.verifyExactNextKeySyncReply(
      wireBytes: wrongVariant.wire,
      context: wrongVariant.context,
      capability: capability
    )
    XCTAssertThrowsError(
      try verifier.openExactNextKeySyncReply(wrongVariantCandidate)
    ) { error in
      XCTAssertEqual(error as? MachineDataVerifierError, .unexpectedKeyControlVariant)
    }
    guard
      case .directoryCurrent(let current) =
        try verifier.openExactNextKeySyncResponse(wrongVariantCandidate)
    else {
      return XCTFail("typed KeySync response must preserve DirectoryCurrent")
    }
    XCTAssertEqual(current.authority, authority)
    XCTAssertEqual(current.currentKeyDirectoryRevision, 7)
    XCTAssertEqual(current.requestedKeyDirectoryRevision, 8)

    let wrongHeaderSet = try keySyncReplyFrame(
      fixture: fixture,
      requestRoute: requestRoute,
      headerRevision: 8,
      keyID: KeyIDV1(purpose: .deviceReplyTx, epoch: 1),
      rawKeyByte: 0x43,
      controlBytes: DaemonKeyControlCanonicalCodec.encode(
        .updateSet(try KeyUpdateSetCanonicalCodec.decode(skippedSetBytes))
      )
    )
    let wrongHeaderCandidate = try verifier.verifyExactNextKeySyncReply(
      wireBytes: wrongHeaderSet.wire,
      context: wrongHeaderSet.context,
      capability: capability
    )
    XCTAssertThrowsError(
      try verifier.openExactNextKeySyncReply(wrongHeaderCandidate)
    ) { error in
      XCTAssertEqual(error as? MachineDataVerifierError, .keyControlRevisionMismatch)
    }
  }
}

struct KeyUpdateSetCryptoFixture {
  let revision: UInt64 = 8
  let relayServerID = Data(repeating: 0x81, count: 16)
  let machineRoute = Data(repeating: 0x82, count: 16)
  let deviceRoute = Data(repeating: 0x83, count: 16)
  let rootKeyID = Data(repeating: 0x84, count: 16)
  let dataSigningKey: Curve25519.Signing.PrivateKey
  let hpkePrivateKey: Curve25519.KeyAgreement.PrivateKey
  let keyVerifier: KeyDirectoryVerifier
  let setVerifier: KeyUpdateSetVerifier

  init() throws {
    let rootKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x85, count: 32)
    )
    dataSigningKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x86, count: 32)
    )
    hpkePrivateKey = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: Data(repeating: 0x87, count: 32)
    )
    let certificate = RelayV2SignedCertificate(
      subjectPubkey: dataSigningKey.publicKey.rawRepresentation,
      certRole: .data,
      generation: 4,
      rootKeyId: rootKeyID,
      trustEpoch: 3,
      notAfterMs: 4_000_000_000_000,
      signature: Data(repeating: 0x88, count: 64)
    )
    let record = try StoredPairedMachineRecordV1(
      clientKind: .macOSApp,
      installationID: UUID(uuidString: "82000000-0000-0000-0000-000000000001")!,
      machineID: "key-update-set-machine",
      machineName: "Key Update Set Machine",
      relayURL: URL(string: "wss://relay.example.com/")!,
      relayServerID: relayServerID,
      machineRootPublicKey: rootKey.publicKey.rawRepresentation,
      machineRootFingerprint: CanonicalCodec.sha256(rootKey.publicKey.rawRepresentation),
      machineDataCertificate: certificate,
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      currentSPKIPin: Data(repeating: 0x89, count: 32),
      nextSPKIPin: nil,
      grantSerial: 9,
      trustEpoch: 3,
      createdAtMS: 1
    )
    keyVerifier = try KeyDirectoryVerifier(
      record: record,
      verifiedCertificate: VerifiedMachineDataCertificate(
        certificate: certificate,
        signingKey: dataSigningKey.publicKey
      ),
      deviceHPKEPrivateKey: hpkePrivateKey
    )
    setVerifier = KeyUpdateSetVerifier(keyVerifier: keyVerifier)
  }

  func signedUpdate(
    purpose: KeyPurpose,
    streamRoute: Data?,
    rawKey: Data,
    epoch: UInt64? = nil,
    revision selectedRevision: UInt64? = nil,
    tamperWrappedKeyBeforeSigning: Bool = false
  ) throws -> CanonicalKeyUpdateV1 {
    let revision = selectedRevision ?? self.revision
    let keyID = KeyIDV1(
      purpose: purpose,
      epoch: epoch ?? (purpose == .conversationDEK ? 4 : 1)
    )
    let sealing = try keyVerifier.sealingContext(
      keyDirectoryRevision: revision,
      keyID: keyID,
      streamRoute: streamRoute
    )
    let envelope = try RelayCrypto.sealHPKE(
      rawKey,
      recipient: hpkePrivateKey.publicKey,
      info: sealing.info,
      aad: CanonicalCodec.encodeAAD(sealing.outerContext)
    )
    var wrappedKey = envelope.ciphertext
    if tamperWrappedKeyBeforeSigning { wrappedKey[0] ^= 1 }
    let unsigned = try CanonicalKeyUpdateV1(
      keyDirectoryRevision: revision,
      keyID: keyID,
      deviceRoute: deviceRoute,
      streamRoute: streamRoute,
      enc: envelope.enc,
      wrappedKey: wrappedKey,
      signature: Data(repeating: 0, count: 64),
      requireSignature: false
    )
    let signature = try dataSigningKey.signature(
      for: keyVerifier.keyUpdateSignatureTBS(unsigned, sealing: sealing)
    )
    return try replacing(unsigned, signature: signature)
  }

  func signedDirectory(
    revision: UInt64,
    materials: [LifecycleTestMaterial]
  ) throws -> (directory: DeviceKeyDirectoryV1, canonical: Data) {
    let entries = try materials.map { material in
      let keyID = KeyIDV1(purpose: material.purpose, epoch: material.epoch)
      let sealing = try keyVerifier.sealingContext(
        keyDirectoryRevision: revision,
        keyID: keyID,
        streamRoute: material.streamRoute
      )
      let envelope = try RelayCrypto.sealHPKE(
        material.rawKey,
        recipient: hpkePrivateKey.publicKey,
        info: sealing.info,
        aad: CanonicalCodec.encodeAAD(sealing.outerContext)
      )
      return try DeviceWrappedKeyV1(
        keyID: keyID,
        deviceRoute: deviceRoute,
        streamRoute: material.streamRoute,
        enc: envelope.enc,
        wrappedKey: envelope.ciphertext
      )
    }
    let unsigned = try DeviceKeyDirectoryV1(
      revision: revision,
      entries: entries,
      signature: Data(repeating: 1, count: 64)
    )
    let signed = try DeviceKeyDirectoryV1(
      revision: revision,
      entries: entries,
      signature: dataSigningKey.signature(for: keyVerifier.directorySignatureTBS(unsigned))
    )
    return (signed, try KeyDirectoryCanonicalCodec.encode(signed))
  }

  func signedUpdateSet(
    revision: UInt64,
    materials: [LifecycleTestMaterial]
  ) throws -> Data {
    let updates = try materials.map { material in
      try signedUpdate(
        purpose: material.purpose,
        streamRoute: material.streamRoute,
        rawKey: material.rawKey,
        epoch: material.epoch,
        revision: revision
      )
    }
    return try KeyUpdateSetCanonicalCodec.encode(
      CanonicalKeyUpdateSetV1(
        keyDirectoryRevision: revision,
        deviceRoute: deviceRoute,
        updates: updates
      ))
  }
}

struct LifecycleTestMaterial {
  let purpose: KeyPurpose
  let epoch: UInt64
  let streamRoute: Data?
  let rawKeyByte: UInt8

  var rawKey: Data { Data(repeating: rawKeyByte, count: 32) }
}

struct BootstrapEpochZeroFixture {
  let crypto: KeyUpdateSetCryptoFixture
  let initialState: DeviceCryptoStateV1
  let expectedConversationRoutes: [Data]
  let barriers: [DeviceEpochBarrierV1]
}

func makeBootstrapEpochZeroFixture() throws -> BootstrapEpochZeroFixture {
  let crypto = try KeyUpdateSetCryptoFixture()
  let catalogStreamRoute = Data(repeating: 0xC1, count: 16)
  let conversationRoutes = [
    Data(repeating: 0xC2, count: 16),
    Data(repeating: 0xC3, count: 16),
  ]
  let directory = try crypto.signedDirectory(
    revision: crypto.revision,
    materials: lifecycleBootstrapMaterials(
      conversations: [
        LifecycleTestMaterial(
          purpose: .conversationDEK,
          epoch: 1,
          streamRoute: conversationRoutes[0],
          rawKeyByte: 0x44
        ),
        LifecycleTestMaterial(
          purpose: .conversationDEK,
          epoch: 1,
          streamRoute: conversationRoutes[1],
          rawKeyByte: 0x45
        ),
      ]
    )
  )
  let streamStates = try [
    DeviceStreamCursorStateV1(
      streamRoute: catalogStreamRoute,
      generation: Data(repeating: 0xC4, count: 16),
      outerCursor: .beforeFirst,
      innerCursor: .catalog(.beforeFirst)
    ),
    DeviceStreamCursorStateV1(
      streamRoute: conversationRoutes[0],
      generation: Data(repeating: 0xC5, count: 16),
      outerCursor: .beforeFirst,
      innerCursor: .conversation(id: "bootstrap-conversation-a", cursor: .beforeFirst)
    ),
    DeviceStreamCursorStateV1(
      streamRoute: conversationRoutes[1],
      generation: Data(repeating: 0xC6, count: 16),
      outerCursor: .beforeFirst,
      innerCursor: .conversation(id: "bootstrap-conversation-b", cursor: .beforeFirst)
    ),
  ]
  let initialState = try lifecycleState(
    fixture: crypto,
    directory: directory.directory,
    streamStates: streamStates
  )
  let barriers = try streamStates.map { stream in
    try DeviceEpochBarrierV1(
      streamRoute: stream.streamRoute,
      streamGeneration: stream.generation,
      streamCursor: stream.outerCursor,
      innerCursor: stream.innerCursor,
      oldEpoch: 0,
      newEpoch: 1,
      keyDirectoryRevision: crypto.revision
    )
  }
  return BootstrapEpochZeroFixture(
    crypto: crypto,
    initialState: initialState,
    expectedConversationRoutes: conversationRoutes,
    barriers: barriers
  )
}

private struct KeySyncReplyFrameFixture {
  let context: OuterContextV1
  let wire: Data
}

private struct LifecyclePublicationFrameFixture {
  let context: OuterContextV1
  let wire: Data
}

private func lifecyclePublicationFrame(
  fixture: KeyUpdateSetCryptoFixture,
  streamRoute: Data,
  streamGeneration: Data,
  streamSequence: UInt64,
  headerRevision: UInt64,
  keyID: KeyIDV1,
  rawKeyByte: UInt8,
  payloadKind: SealedPayloadKind,
  payload: Data,
  counter: UInt64
) throws -> LifecyclePublicationFrameFixture {
  let frameKind: OuterFrameKind
  switch keyID.purpose {
  case .catalog:
    frameKind = .catalogPublish
  case .conversationDEK:
    frameKind = .conversationPublish
  case .deviceCommandTx, .deviceReplyTx:
    throw MachineDataVerifierError.receivingKeyMismatch
  }
  let context = OuterContextV1(
    frameKind: frameKind,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.machineRoute,
    deviceRoute: nil,
    streamRoute: streamRoute,
    requestRoute: nil,
    streamGeneration: streamGeneration,
    streamCursor: nil,
    streamSeq: streamSequence,
    messageKeyEpoch: keyID.epoch
  )
  let sendingKey = try AeadSendingKey(
    keyID: keyID,
    epoch: keyID.epoch,
    keyDirectoryRevision: headerRevision,
    payloadKind: payloadKind,
    rawKey: Data(repeating: rawKeyByte, count: 32)
  )
  let unsigned = try RelayCrypto.sealSymmetric(
    payload,
    key: sendingKey,
    context: context,
    counter: counter
  )
  let signed = try RelayCrypto.signSealed(
    unsigned,
    key: fixture.dataSigningKey,
    context: context
  )
  return LifecyclePublicationFrameFixture(
    context: context,
    wire: try RelayV2SignedSealedBlobCodec.encode(
      signed,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
  )
}

private func lifecycleMachineDataVerifier(
  fixture: KeyUpdateSetCryptoFixture,
  currentRevision: UInt64
) throws -> MachineDataVerifier {
  try MachineDataVerifier(
    machineRoute: fixture.machineRoute,
    deviceRoute: fixture.deviceRoute,
    verifiedCertificate: VerifiedMachineDataCertificate(
      certificate: RelayV2SignedCertificate(
        subjectPubkey: fixture.dataSigningKey.publicKey.rawRepresentation,
        certRole: .data,
        generation: 4,
        rootKeyId: fixture.rootKeyID,
        trustEpoch: 3,
        notAfterMs: nil,
        signature: Data(repeating: 0xD4, count: 64)
      ),
      signingKey: fixture.dataSigningKey.publicKey
    ),
    currentKeyDirectoryRevision: currentRevision,
    maximumKeySyncAdvance: 1
  )
}

private func lifecycleKeySyncEpisode(
  targetRevision: UInt64,
  observedKeyID: KeyIDV1
) throws -> DeviceKeySyncEpisodeV1 {
  try DeviceKeySyncEpisodeV1(
    targetRevision: targetRevision,
    observedKeyID: observedKeyID,
    streamRoute: nil,
    attempt: 1,
    startedAtMS: LifecycleReplayEnvironment.clockMS,
    expiresAtMS: LifecycleReplayEnvironment.clockMS
      + DeviceKeySyncEpisodeV1.deadlineMilliseconds
  )
}

private func copiedLifecycleState(
  _ state: DeviceCryptoStateV1,
  stateRevision: UInt64? = nil,
  streamStates: [DeviceStreamCursorStateV1],
  keySyncEpisode: DeviceKeySyncEpisodeV1?
) throws -> DeviceCryptoStateV1 {
  try DeviceCryptoStateV1(
    stateRevision: stateRevision ?? state.stateRevision,
    trustScope: state.trustScope,
    keyDirectory: state.keyDirectory,
    senderCounter: state.senderCounter,
    securityState: state.securityState,
    replayStates: state.replayStates,
    streamStates: streamStates,
    keyLifecycle: state.keyLifecycle,
    pendingStreamBindings: state.pendingStreamBindings,
    keySyncEpisode: keySyncEpisode
  )
}

private actor LifecycleMemoryKeyStore: KeyStore {
  private var values: [KeyStoreKey: Data] = [:]

  func load(_ key: KeyStoreKey) async throws -> Data? {
    values[key]
  }

  func persistImmutable(
    _ data: Data,
    for key: KeyStoreKey
  ) async throws -> KeyStorePersistence {
    if let current = values[key] {
      guard current == data else { throw KeyStoreError.immutableConflict }
      return .alreadyPresent
    }
    values[key] = data
    return .inserted
  }

  func compareAndReplaceExact(
    expected: Data,
    replacement: Data,
    for key: KeyStoreKey
  ) async throws {
    guard let current = values[key] else {
      throw KeyStoreError.compareAndReplaceMissing
    }
    guard current == expected else {
      throw KeyStoreError.compareAndReplaceMismatch
    }
    values[key] = replacement
  }

  func deleteExact(expected: Data, for key: KeyStoreKey) async throws {
    guard let current = values[key] else {
      throw KeyStoreError.compareAndReplaceMissing
    }
    guard current == expected else {
      throw KeyStoreError.compareAndReplaceMismatch
    }
    values.removeValue(forKey: key)
  }
}

private struct LifecycleReplayEnvironment {
  static let clockMS: UInt64 = 1_750_000_000_000

  let rootURL: URL
  let stateStore: FileCryptoStateStore
  let keyStore: LifecycleMemoryKeyStore
  let identity: CryptoStateIdentity
  let guardKey: KeyStoreKey
  let snapshot: CryptoStateSnapshot

  init(state: DeviceCryptoStateV1) throws {
    rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "AgentDeckLifecycleCryptoTests-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: rootURL,
      withIntermediateDirectories: true
    )
    identity = try CryptoStateIdentity(
      clientKind: .macOSApp,
      installationID: UUID(uuidString: "b0000000-0000-0000-0000-000000000001")!,
      machineID: "lifecycle-crypto-test",
      machineRootFingerprint: state.trustScope.machineRootFingerprint,
      machineRoute: state.trustScope.machineRoute
    )
    stateStore = try FileCryptoStateStore(
      rootURL: rootURL,
      identity: identity,
      storageKey: DeviceStorageKEK(
        rawRepresentation: Data(repeating: 0xE1, count: 32)
      ),
      testHooks: .none,
      testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
    )
    keyStore = LifecycleMemoryKeyStore()
    guardKey = try KeyStoreKey.paired(
      clientKind: identity.clientKind,
      installationID: identity.installationID,
      rootFingerprint: identity.machineRootFingerprint,
      machineRoute: identity.machineRoute,
      purpose: .counterGuard
    )
    snapshot = try CryptoStateSnapshot(state)
  }

  func start() async throws -> DurableCryptoStateCoordinator {
    let coordinator = try DurableCryptoStateCoordinator(
      rootURL: rootURL,
      identity: identity,
      stateStore: stateStore,
      keyStore: keyStore,
      guardKey: guardKey,
      observer: nil,
      reservationIDGenerator: { Data(repeating: 0xE2, count: 16) },
      clock: { Self.clockMS }
    )
    guard try await stateStore.commitInitial(snapshot) == .created else {
      throw CryptoStateStoreError.immutableConflict
    }
    _ = try await coordinator.bootstrap(
      CounterBootstrapPermit(
        snapshot: snapshot,
        promotionID: Data(repeating: 0xE3, count: 32)
      ))
    return coordinator
  }

  func removeSandbox() {
    try? FileManager.default.removeItem(at: rootURL)
  }
}

private func keySyncReplyFrame(
  fixture: KeyUpdateSetCryptoFixture,
  requestRoute: Data,
  headerRevision: UInt64,
  keyID: KeyIDV1,
  rawKeyByte: UInt8,
  controlBytes: Data
) throws -> KeySyncReplyFrameFixture {
  let context = OuterContextV1(
    frameKind: .directedReply,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.machineRoute,
    deviceRoute: fixture.deviceRoute,
    streamRoute: nil,
    requestRoute: requestRoute,
    streamGeneration: nil,
    streamCursor: nil,
    streamSeq: nil,
    messageKeyEpoch: keyID.epoch
  )
  let sendingKey = try AeadSendingKey(
    keyID: keyID,
    epoch: keyID.epoch,
    keyDirectoryRevision: headerRevision,
    payloadKind: .keyUpdate,
    rawKey: Data(repeating: rawKeyByte, count: 32)
  )
  let unsigned = try RelayCrypto.sealSymmetric(
    controlBytes,
    key: sendingKey,
    context: context,
    counter: 1
  )
  let signed = try RelayCrypto.signSealed(
    unsigned,
    key: fixture.dataSigningKey,
    context: context
  )
  return KeySyncReplyFrameFixture(
    context: context,
    wire: try RelayV2SignedSealedBlobCodec.encode(
      signed,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
  )
}

func lifecycleBootstrapMaterials(
  conversations: [LifecycleTestMaterial] = []
) -> [LifecycleTestMaterial] {
  [LifecycleTestMaterial(purpose: .catalog, epoch: 1, streamRoute: nil, rawKeyByte: 0x41)]
    + conversations
    + [
      LifecycleTestMaterial(
        purpose: .deviceCommandTx,
        epoch: 1,
        streamRoute: nil,
        rawKeyByte: 0x42
      ),
      LifecycleTestMaterial(
        purpose: .deviceReplyTx,
        epoch: 1,
        streamRoute: nil,
        rawKeyByte: 0x43
      ),
    ]
}

func lifecycleState(
  fixture: KeyUpdateSetCryptoFixture,
  directory: DeviceKeyDirectoryV1,
  streamStates: [DeviceStreamCursorStateV1] = []
) throws -> DeviceCryptoStateV1 {
  let rootKey = try Curve25519.Signing.PrivateKey(
    rawRepresentation: Data(repeating: 0x85, count: 32)
  )
  let replayStates = try directory.entries.compactMap { entry -> DeviceReplayStateV1? in
    guard entry.keyID.purpose != .deviceCommandTx else { return nil }
    return try DeviceReplayStateV1(
      scope: DeviceCryptoKeyScopeV1(keyID: entry.keyID, streamRoute: entry.streamRoute),
      window: ReplayWindowSnapshot(highWater: nil, floor: 0, entries: []),
      status: .active
    )
  }
  let commandKeyID = KeyIDV1(purpose: .deviceCommandTx, epoch: 1)
  let commandCapability = try AeadSendingKey(
    keyID: commandKeyID,
    epoch: commandKeyID.epoch,
    keyDirectoryRevision: directory.revision,
    payloadKind: .commandRequest,
    rawKey: Data(repeating: 0x42, count: 32)
  )
  return try DeviceCryptoStateV1(
    stateRevision: 1,
    trustScope: DeviceCryptoTrustScopeV1(
      relayServerID: fixture.relayServerID,
      machineRootFingerprint: CanonicalCodec.sha256(rootKey.publicKey.rawRepresentation),
      machineRoute: fixture.machineRoute,
      deviceRoute: fixture.deviceRoute,
      grantSerial: 9,
      trustEpoch: 3
    ),
    keyDirectory: directory,
    senderCounter: DeviceSenderCounterV1(
      keyID: commandKeyID,
      keyDirectoryRevision: directory.revision,
      noncePrefix: commandCapability.noncePrefix,
      reservedHighWater: 0,
      reservationID: Data(repeating: 0, count: 16)
    ),
    securityState: .active,
    replayStates: replayStates,
    streamStates: streamStates
  )
}

private func syntheticUpdate(
  purpose: KeyPurpose,
  streamRoute: Data?,
  marker: UInt8,
  deviceRoute: Data,
  epoch: UInt64? = nil
) throws -> CanonicalKeyUpdateV1 {
  try CanonicalKeyUpdateV1(
    keyDirectoryRevision: 8,
    keyID: KeyIDV1(
      purpose: purpose,
      epoch: epoch ?? (purpose == .conversationDEK ? 4 : 1)
    ),
    deviceRoute: deviceRoute,
    streamRoute: streamRoute,
    enc: Data(repeating: marker == 0 ? 1 : marker, count: 32),
    wrappedKey: Data(repeating: marker &+ 1 == 0 ? 1 : marker &+ 1, count: 48),
    signature: Data(repeating: marker &+ 2 == 0 ? 1 : marker &+ 2, count: 64)
  )
}

private func replacing(
  _ update: CanonicalKeyUpdateV1,
  signature: Data
) throws -> CanonicalKeyUpdateV1 {
  try CanonicalKeyUpdateV1(
    keyDirectoryRevision: update.keyDirectoryRevision,
    keyID: update.keyID,
    deviceRoute: update.deviceRoute,
    streamRoute: update.streamRoute,
    enc: update.enc,
    wrappedKey: update.wrappedKey,
    signature: signature
  )
}

private func route(_ value: UInt64) -> Data {
  var route = Data(repeating: 0, count: 8)
  var encoded = value.bigEndian
  Swift.withUnsafeBytes(of: &encoded) { route.append(contentsOf: $0) }
  return route
}

private func rawSet(
  revision: UInt64,
  deviceRoute: Data,
  updateCarriers: [Data]
) -> Data {
  var output = Data("AgentDeck/KeyUpdateSetV1\0".utf8)
  appendInteger(revision, to: &output)
  appendBytes(deviceRoute, to: &output)
  appendInteger(UInt16(updateCarriers.count), to: &output)
  for carrier in updateCarriers { appendBytes(carrier, to: &output) }
  return output
}

private func appendBytes(_ value: Data, to output: inout Data) {
  appendInteger(UInt32(value.count), to: &output)
  output.append(value)
}

private func appendInteger<T: FixedWidthInteger>(_ value: T, to output: inout Data) {
  var encoded = value.bigEndian
  Swift.withUnsafeBytes(of: &encoded) { output.append(contentsOf: $0) }
}

private func loadKeyUpdateSetVector() throws -> [String: Any] {
  let root = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
  let url = root.appendingPathComponent("protocol/agentdeck/crypto-vectors-v1.json")
  let object = try XCTUnwrap(
    try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
  )
  return try XCTUnwrap(object["key_update_set_canonical"] as? [String: Any])
}

private func keyUpdateSetVectorData(
  _ key: String,
  in section: [String: Any]
) throws -> Data {
  try decodeKeyUpdateSetVectorHex(try XCTUnwrap(section[key] as? String))
}

private func keyUpdateSetVectorDataArray(
  _ key: String,
  in section: [String: Any]
) throws -> [Data] {
  try XCTUnwrap(section[key] as? [String]).map(decodeKeyUpdateSetVectorHex)
}

private func keyUpdateSetVectorUInt64(
  _ key: String,
  in section: [String: Any]
) throws -> UInt64 {
  let value = try XCTUnwrap(section[key] as? NSNumber)
  guard value.int64Value >= 0 else { throw KeyUpdateSetVectorError.invalidNumber }
  return value.uint64Value
}

private func decodeKeyUpdateSetVectorHex(_ value: String) throws -> Data {
  guard value.count.isMultiple(of: 2) else {
    throw KeyUpdateSetVectorError.invalidHex
  }
  var output = Data()
  output.reserveCapacity(value.count / 2)
  var index = value.startIndex
  while index < value.endIndex {
    let next = value.index(index, offsetBy: 2)
    guard let byte = UInt8(value[index..<next], radix: 16) else {
      throw KeyUpdateSetVectorError.invalidHex
    }
    output.append(byte)
    index = next
  }
  return output
}

private enum KeyUpdateSetVectorError: Error {
  case invalidHex
  case invalidNumber
}

extension Data {
  fileprivate var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
