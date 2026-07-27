import AgentDeckSessionSource
import Foundation
import XCTest

@testable import AgentDeckMobile

@MainActor
final class AppLifecycleTests: XCTestCase {
    func testForegroundBuildsOneSourceAndConcurrentCallsShareTheSameGeneration() async {
        let first = SessionSourceSpy()
        let factory = MobileSessionSourceFactorySpy(sources: [first])
        let root = CompositionRoot(factory: factory)
        var readyGenerations: [UInt64] = []
        root.onSourceReady = { _, generation in readyGenerations.append(generation) }

        async let left: Void = root.enterForeground()
        async let right: Void = root.enterForeground()
        _ = await (left, right)

        let makeCount = await factory.makeCount()
        let shutdownCount = await first.shutdownCount()
        XCTAssertEqual(makeCount, 1)
        XCTAssertEqual(readyGenerations, [1])
        XCTAssertEqual(root.state, .active(generation: 1))
        XCTAssertEqual(shutdownCount, 0)
    }

    func testBackgroundShutsDownCurrentSourceExactlyOnceAndPublishesSuspended() async {
        let source = SessionSourceSpy()
        let factory = MobileSessionSourceFactorySpy(sources: [source])
        let root = CompositionRoot(factory: factory)
        await root.enterForeground()

        await root.enterBackground()
        await root.enterBackground()

        let shutdownCount = await source.shutdownCount()
        XCTAssertEqual(shutdownCount, 1)
        XCTAssertEqual(root.state, .suspended)
    }

    func testForegroundAfterBackgroundBuildsFreshSourceForColdOuterAndInnerResume() async {
        let first = SessionSourceSpy()
        let second = SessionSourceSpy()
        let factory = MobileSessionSourceFactorySpy(sources: [first, second])
        let root = CompositionRoot(factory: factory)

        await root.enterForeground()
        await root.enterBackground()
        await root.enterForeground()

        let makeCount = await factory.makeCount()
        let firstShutdownCount = await first.shutdownCount()
        let secondShutdownCount = await second.shutdownCount()
        XCTAssertEqual(makeCount, 2)
        XCTAssertEqual(firstShutdownCount, 1)
        XCTAssertEqual(secondShutdownCount, 0)
        XCTAssertEqual(root.state, .active(generation: 2))
    }

    func testReloadAfterPairingMutationShutsOldSourceBeforePublishingReplacement() async {
        let first = SessionSourceSpy()
        let second = SessionSourceSpy()
        let factory = MobileSessionSourceFactorySpy(sources: [first, second])
        let root = CompositionRoot(factory: factory)
        var observations: [(generation: UInt64, firstShutdowns: Int)] = []
        root.onSourceReady = { _, generation in
            Task { @MainActor in
                observations.append((generation, await first.shutdownCount()))
            }
        }
        await root.enterForeground()

        await root.reloadAfterPairedMachineMutation()
        await waitForMainActorState { observations.count == 2 }

        XCTAssertEqual(observations.map(\.generation), [1, 2])
        XCTAssertEqual(observations.last?.firstShutdowns, 1)
        let makeCount = await factory.makeCount()
        XCTAssertEqual(makeCount, 2)
    }

    func testFactoryFailureIsTypedAndForegroundRetryCanRecover() async {
        let source = SessionSourceSpy()
        let factory = MobileSessionSourceFactorySpy(
            outcomes: [
                .failure(SessionSourceFailure(code: .storageUnavailable)),
                .source(source),
            ])
        let root = CompositionRoot(factory: factory)

        await root.enterForeground()
        XCTAssertEqual(
            root.state,
            .failed(SessionSourceFailure(code: .storageUnavailable)))
        await root.enterForeground()

        let makeCount = await factory.makeCount()
        XCTAssertEqual(makeCount, 2)
        XCTAssertEqual(root.state, .active(generation: 2))
    }

    func testBackgroundDuringOpeningDiscardsAndShutsDownLateSource() async {
        let source = SessionSourceSpy()
        let factory = MobileSessionSourceFactorySpy(outcomes: [.suspended(source)])
        let root = CompositionRoot(factory: factory)
        var readyCount = 0
        root.onSourceReady = { _, _ in readyCount += 1 }

        let foreground = Task { @MainActor in await root.enterForeground() }
        await factory.waitForMakeCalls(1)
        let background = Task { @MainActor in await root.enterBackground() }
        await waitForMainActorState { root.state == .suspended }
        await factory.releaseSuspendedSource()
        await background.value
        await foreground.value

        let shutdownCount = await source.shutdownCount()
        XCTAssertEqual(shutdownCount, 1)
        XCTAssertEqual(root.state, .suspended)
        XCTAssertEqual(readyCount, 0)
    }

    func testCapturedBackgroundIntentInvalidatesLateForegroundJobBeforeItCanOpen() async {
        let source = SessionSourceSpy()
        let factory = MobileSessionSourceFactorySpy(sources: [source])
        let root = CompositionRoot(factory: factory)
        let foregroundRevision = try! XCTUnwrap(root.captureForegroundIntent())
        let backgroundRevision = try! XCTUnwrap(root.captureBackgroundIntent())

        XCTAssertEqual(root.state, .suspended, "background callback 必须同步公开 stop intent")
        await root.fulfillForegroundIntent(foregroundRevision)
        await root.fulfillBackgroundIntent(backgroundRevision)

        let makeCount = await factory.makeCount()
        let shutdownCount = await source.shutdownCount()
        XCTAssertEqual(makeCount, 0, "迟到 foreground job 不得在较新 background 后 cold-open")
        XCTAssertEqual(shutdownCount, 0)
        XCTAssertEqual(root.state, .suspended)
    }

    func testCapturedBackgroundIntentCancelsOpeningBeforeAsyncFulfillmentRuns() async {
        let source = SessionSourceSpy()
        let factory = MobileSessionSourceFactorySpy(outcomes: [.suspended(source)])
        let root = CompositionRoot(factory: factory)
        let foreground = Task { @MainActor in await root.enterForeground() }
        await factory.waitForMakeCalls(1)

        let backgroundRevision = try! XCTUnwrap(root.captureBackgroundIntent())
        XCTAssertEqual(root.state, .suspended)
        await factory.releaseSuspendedSource()
        await root.fulfillBackgroundIntent(backgroundRevision)
        await foreground.value

        let shutdownCount = await source.shutdownCount()
        XCTAssertEqual(shutdownCount, 1)
        XCTAssertEqual(root.state, .suspended)
    }

    func testDisconnectWorkerRetainsDelegateUntilCapturedShutdownFinishes() async {
        let source = SessionSourceSpy()
        await source.suspendShutdown()
        let factory = MobileSessionSourceFactorySpy(sources: [source])
        let root = CompositionRoot(factory: factory)
        await root.enterForeground()

        weak var releasedDelegate: SceneDelegate?
        do {
            var delegate: SceneDelegate? = SceneDelegate(testingCompositionRoot: root)
            releasedDelegate = delegate
            delegate?.requestBackgroundForTesting()
            delegate = nil
        }

        await source.waitForShutdowns(1)
        XCTAssertNotNil(releasedDelegate, "drain 完成前 worker 必须强持有 scene delegate")
        await source.releaseShutdown()
        await waitForMainActorState { releasedDelegate == nil }
        XCTAssertEqual(root.state, .suspended)
    }

    func testBackgroundThenForegroundDuringOpeningRejectsOldOpeningGeneration() async {
        let first = SessionSourceSpy()
        let second = SessionSourceSpy()
        let factory = MobileSessionSourceFactorySpy(
            outcomes: [.suspended(first), .source(second)]
        )
        let root = CompositionRoot(factory: factory)

        let oldForeground = Task { @MainActor in await root.enterForeground() }
        await factory.waitForMakeCalls(1)
        let background = Task { @MainActor in await root.enterBackground() }
        await waitForMainActorState { root.state == .suspended }
        let newForeground = Task { @MainActor in await root.enterForeground() }
        await factory.releaseSuspendedSource()

        await oldForeground.value
        await background.value
        await newForeground.value

        let makeCount = await factory.makeCount()
        let firstShutdowns = await first.shutdownCount()
        XCTAssertEqual(makeCount, 2)
        XCTAssertEqual(firstShutdowns, 1)
        XCTAssertEqual(root.state, .active(generation: 2))
    }

    func testForegroundWaitsForActiveSourceShutdownBeforeOpeningReplacement() async {
        let first = SessionSourceSpy()
        let second = SessionSourceSpy()
        await first.suspendShutdown()
        let factory = MobileSessionSourceFactorySpy(sources: [first, second])
        let root = CompositionRoot(factory: factory)
        await root.enterForeground()

        let background = Task { @MainActor in await root.enterBackground() }
        await first.waitForShutdowns(1)
        let foreground = Task { @MainActor in await root.enterForeground() }
        try? await Task.sleep(for: .milliseconds(20))
        let countBeforeRelease = await factory.makeCount()
        XCTAssertEqual(countBeforeRelease, 1)

        await first.releaseShutdown()
        await background.value
        await foreground.value

        let finalCount = await factory.makeCount()
        XCTAssertEqual(finalCount, 2)
        XCTAssertEqual(root.state, .active(generation: 2))
    }

    func testVerifiedRevocationIsDeletedWithoutOpeningPairingScreen() async {
        let first = SessionSourceSpy()
        let second = SessionSourceSpy()
        let probe = LocalForgetOperationProbe()
        let manager = ClosureTestLocalPairedMachineManager { machineID in
            await probe.record(
                machineID: machineID,
                shutdownCount: await first.shutdownCount()
            )
        }
        let factory = MobileSessionSourceFactorySpy(
            outcomes: [.sourceWithManager(first, manager), .source(second)]
        )
        let root = CompositionRoot(factory: factory)
        await root.enterForeground()
        await first.waitForMachineSubscriptions(1)

        await first.emitMachines(
            .ready(
                value: [
                    MachineSummary(
                        id: "machine-1",
                        name: "Mac Studio",
                        connectionState: .revoked,
                        lastHeartbeat: nil,
                        activeConversationCount: 0,
                        pendingApprovalCount: 0
                    )
                ],
                revision: 1
            )
        )

        await probe.waitForCalls(1)
        await factory.waitForMakeCalls(2)
        await waitForMainActorState { root.state == .active(generation: 2) }
        let calls = await probe.recordedCalls()
        let firstShutdownCount = await first.shutdownCount()
        XCTAssertEqual(calls, [.init(machineID: "machine-1", shutdownCount: 1)])
        XCTAssertEqual(firstShutdownCount, 1)
    }

    func testVerifiedRevocationDeleteFailureFailsClosedWithoutReopenLoop() async {
        let source = SessionSourceSpy()
        let manager = ClosureTestLocalPairedMachineManager { _ in
            throw SessionSourceFailure(code: .storageUnavailable)
        }
        let factory = MobileSessionSourceFactorySpy(
            outcomes: [.sourceWithManager(source, manager)]
        )
        let root = CompositionRoot(factory: factory)
        await root.enterForeground()
        await source.waitForMachineSubscriptions(1)

        await source.emitMachines(
            .ready(
                value: [
                    MachineSummary(
                        id: "machine-1",
                        name: "Mac Studio",
                        connectionState: .revoked,
                        lastHeartbeat: nil,
                        activeConversationCount: 0,
                        pendingApprovalCount: 0
                    )
                ],
                revision: 1
            )
        )
        await waitForMainActorState {
            root.state == .failed(SessionSourceFailure(code: .storageUnavailable))
        }

        let makeCount = await factory.makeCount()
        let shutdownCount = await source.shutdownCount()
        XCTAssertEqual(makeCount, 1)
        XCTAssertEqual(shutdownCount, 1)
    }

    func testStaleGenerationRevokedTerminalCannotDeleteNewPairingRecord() async {
        let first = SessionSourceSpy()
        let second = SessionSourceSpy()
        let oldManager = LocalPairedMachineStoreSpy()
        let newManager = LocalPairedMachineStoreSpy()
        let factory = MobileSessionSourceFactorySpy(
            outcomes: [
                .sourceWithManager(first, oldManager),
                .sourceWithManager(second, newManager),
            ]
        )
        let root = CompositionRoot(factory: factory)
        await root.enterForeground()
        await first.waitForMachineSubscriptions(1)
        await root.reloadAfterPairedMachineMutation()

        await first.emitMachines(
            .ready(
                value: [
                    MachineSummary(
                        id: "machine-1",
                        name: "Mac Studio",
                        connectionState: .revoked,
                        lastHeartbeat: nil,
                        activeConversationCount: 0,
                        pendingApprovalCount: 0
                    )
                ],
                revision: 1
            )
        )
        try? await Task.sleep(for: .milliseconds(20))

        let oldCalls = await oldManager.recordedForgetCalls()
        let newCalls = await newManager.recordedForgetCalls()
        XCTAssertEqual(oldCalls, [])
        XCTAssertEqual(newCalls, [])
    }

    func testPairedMachineMutationWhileBackgroundedDoesNotOpenRelay() async {
        let first = SessionSourceSpy()
        let factory = MobileSessionSourceFactorySpy(sources: [first])
        let root = CompositionRoot(factory: factory)
        await root.enterForeground()
        await root.enterBackground()

        await root.reloadAfterPairedMachineMutation()

        let makeCount = await factory.makeCount()
        let shutdownCount = await first.shutdownCount()
        XCTAssertEqual(makeCount, 1)
        XCTAssertEqual(shutdownCount, 1)
        XCTAssertEqual(root.state, .suspended)
    }

    func testApplicationStoragePersistsCanonicalInstallationIDAcrossReopen() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "agentdeck-mobile-storage-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let first = try MobileApplicationStorage.open(applicationSupportURL: root)
        let second = try MobileApplicationStorage.open(applicationSupportURL: root)

        XCTAssertEqual(second, first)
        XCTAssertNotEqual(
            first.installationID,
            UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        )
        let record = first.stateRootURL.appendingPathComponent(
            MobileApplicationStorage.installationIDFileName
        )
        XCTAssertEqual(
            try Data(contentsOf: record),
            Data((first.installationID.uuidString.lowercased() + "\n").utf8)
        )
    }

    func testApplicationStorageCorruptInstallationIDFailsClosedWithoutRotation() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "agentdeck-mobile-storage-corrupt-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let initial = try MobileApplicationStorage.open(applicationSupportURL: root)
        let record = initial.stateRootURL.appendingPathComponent(
            MobileApplicationStorage.installationIDFileName
        )
        let corrupt = Data("00000000-0000-0000-0000-000000000000\n".utf8)
        try corrupt.write(to: record, options: .atomic)

        XCTAssertThrowsError(
            try MobileApplicationStorage.open(applicationSupportURL: root)
        ) { error in
            XCTAssertEqual(
                error as? SessionSourceFailure,
                SessionSourceFailure(code: .storageUnavailable)
            )
        }
        XCTAssertEqual(try Data(contentsOf: record), corrupt)
    }

    func testApplicationStorageIsPrivateAndExcludedFromBackup() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "agentdeck-mobile-storage-policy-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let storage = try MobileApplicationStorage.open(applicationSupportURL: root)
        let record = storage.stateRootURL.appendingPathComponent(
            MobileApplicationStorage.installationIDFileName
        )
        let rootValues = try storage.stateRootURL.resourceValues(
            forKeys: [.isExcludedFromBackupKey]
        )
        let recordValues = try record.resourceValues(
            forKeys: [.isExcludedFromBackupKey]
        )
        let rootAttributes = try FileManager.default.attributesOfItem(
            atPath: storage.stateRootURL.path
        )
        let recordAttributes = try FileManager.default.attributesOfItem(atPath: record.path)

        XCTAssertEqual(rootValues.isExcludedFromBackup, true)
        XCTAssertEqual(recordValues.isExcludedFromBackup, true)
        XCTAssertEqual(rootAttributes[.posixPermissions] as? NSNumber, NSNumber(value: 0o700))
        XCTAssertEqual(recordAttributes[.posixPermissions] as? NSNumber, NSNumber(value: 0o600))
    }

    func testLaunchArgumentAcceptsOnlyCompletePairInvite() {
        XCTAssertEqual(
            MobileLaunchOptions(
                arguments: ["AgentDeckMobile", "--pair-invite", "agentdeck-pair:v1:YWJjZA"]
            ).pairInvite,
            "agentdeck-pair:v1:YWJjZA"
        )
        XCTAssertNil(
            MobileLaunchOptions(
                arguments: ["AgentDeckMobile", "--pair-invite", "123456"]
            ).pairInvite
        )
        XCTAssertNil(
            MobileLaunchOptions(arguments: ["AgentDeckMobile", "--pair-invite"]).pairInvite
        )
        XCTAssertTrue(
            MobileLaunchOptions(
                arguments: ["AgentDeckMobile", MobileLaunchOptions.fixtureArgument]
            ).usesFixtureSource
        )
        XCTAssertFalse(
            MobileLaunchOptions(arguments: ["AgentDeckMobile"]).usesFixtureSource
        )
    }

    func testApplicationDeclaresCameraUsageButDoesNotRequestBackgroundExecutionMode() {
        let info = Bundle(for: AppDelegate.self).infoDictionary
        XCTAssertFalse((info?["NSCameraUsageDescription"] as? String)?.isEmpty ?? true)
        XCTAssertNil(info?["UIBackgroundModes"])
    }
}

extension SessionSourceSpy: MobileSessionLifecycleSource {}

actor MobileSessionSourceFactorySpy: MobileSessionSourceBuilding {
    enum Outcome: Sendable {
        case source(SessionSourceSpy)
        case sourceWithManager(SessionSourceSpy, any LocalPairedMachineManaging)
        case failure(SessionSourceFailure)
        case suspended(SessionSourceSpy)
    }

    private var outcomes: [Outcome]
    private let defaultManager: any LocalPairedMachineManaging
    private var calls = 0
    private var suspendedContinuation: CheckedContinuation<MobileSessionContext, any Error>?
    private var suspendedSource: SessionSourceSpy?

    init(
        sources: [SessionSourceSpy],
        localManager: any LocalPairedMachineManaging = NoopLocalPairedMachineManager()
    ) {
        outcomes = sources.map(Outcome.source)
        defaultManager = localManager
    }

    init(
        outcomes: [Outcome],
        localManager: any LocalPairedMachineManaging = NoopLocalPairedMachineManager()
    ) {
        self.outcomes = outcomes
        defaultManager = localManager
    }

    func makeContext() async throws -> MobileSessionContext {
        calls += 1
        guard !outcomes.isEmpty else {
            throw SessionSourceFailure(code: .storageUnavailable)
        }
        switch outcomes.removeFirst() {
        case .source(let source):
            return MobileSessionContext(
                source: source,
                localPairedMachineManager: defaultManager
            )
        case .sourceWithManager(let source, let manager):
            return MobileSessionContext(
                source: source,
                localPairedMachineManager: manager
            )
        case .failure(let failure):
            throw failure
        case .suspended(let source):
            suspendedSource = source
            return try await withCheckedThrowingContinuation { continuation in
                suspendedContinuation = continuation
            }
        }
    }

    func makeCount() -> Int { calls }

    func releaseSuspendedSource() {
        guard let source = suspendedSource else { return }
        suspendedSource = nil
        suspendedContinuation?.resume(
            returning: MobileSessionContext(
                source: source,
                localPairedMachineManager: defaultManager
            )
        )
        suspendedContinuation = nil
    }

    func waitForMakeCalls(_ count: Int) async {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while clock.now < deadline {
            if calls >= count { return }
            try? await Task.sleep(for: .milliseconds(1))
        }
        XCTFail("等待 composition source factory 调用超时")
    }
}

private struct NoopLocalPairedMachineManager: LocalPairedMachineManaging {
    func forgetLocal(machineID: String) async throws {
        _ = machineID
    }
}

private struct ClosureTestLocalPairedMachineManager: LocalPairedMachineManaging {
    let operation: @Sendable (String) async throws -> Void

    func forgetLocal(machineID: String) async throws {
        try await operation(machineID)
    }
}

actor LocalForgetOperationProbe {
    struct Call: Equatable {
        let machineID: String
        let shutdownCount: Int
    }

    private var calls: [Call] = []

    func record(machineID: String, shutdownCount: Int) {
        calls.append(Call(machineID: machineID, shutdownCount: shutdownCount))
    }

    func recordedCalls() -> [Call] { calls }

    func waitForCalls(_ count: Int) async {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while clock.now < deadline {
            if calls.count >= count { return }
            try? await Task.sleep(for: .milliseconds(1))
        }
        XCTFail("等待 local forget operation 调用超时")
    }
}
