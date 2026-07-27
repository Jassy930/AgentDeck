import AgentDeckRelayClient
import AgentDeckSessionSource
import Foundation

protocol MobileSessionLifecycleSource: SessionSource {
    func shutdown() async
}

extension RelaySessionSource: MobileSessionLifecycleSource {}

struct MobileSessionContext: Sendable {
    let source: any MobileSessionLifecycleSource
    let localPairedMachineManager: any LocalPairedMachineManaging
}

protocol MobileSessionSourceBuilding: Sendable {
    func makeContext() async throws -> MobileSessionContext
}

enum MobileCompositionState: Equatable {
    case idle
    case starting(generation: UInt64)
    case active(generation: UInt64)
    case suspended
    case failed(SessionSourceFailure)
}

/// App scene 的唯一 Relay source owner。每次前后台或 paired material 变化都会推进
/// intent revision；旧 opening 只能 shutdown/join，不能在新 intent 中安装。旧 source
/// 完成 shutdown 前禁止 cold-open 下一代，避免两个 WSS owner 重叠。
@MainActor
final class CompositionRoot {
    private let factory: any MobileSessionSourceBuilding

    private(set) var state: MobileCompositionState = .idle {
        didSet { onStateChange?(state) }
    }
    private(set) var currentContext: MobileSessionContext?
    private(set) var currentGeneration: UInt64?
    var currentSource: (any MobileSessionLifecycleSource)? { currentContext?.source }
    var onSourceReady: ((MobileSessionContext, UInt64) -> Void)?
    var onStateChange: ((MobileCompositionState) -> Void)?

    private var openingTask: Task<MobileSessionContext, any Error>?
    private var openingIntentRevision: UInt64?
    private var transitionWaiters: [CheckedContinuation<Void, Never>] = []
    private var generation: UInt64 = 0
    private var intentRevision: UInt64 = 0
    private var foregroundRequested = false
    private var teardownInProgress = false
    private var mutationInProgress = false
    private var verifiedRevocationMonitorTask: Task<Void, Never>?
    private var verifiedRevocationMonitorGeneration: UInt64?

    init(factory: any MobileSessionSourceBuilding) {
        self.factory = factory
    }

    func enterForeground() async {
        guard let requestRevision = captureForegroundIntent() else { return }
        await fulfillForegroundIntent(requestRevision)
    }

    /// UIKit lifecycle callback 内同步冻结 desired state。异步 worker 即使迟到，
    /// `fulfillForegroundIntent` 也只能执行这一个 revision，不能覆盖后到 background。
    @discardableResult
    func captureForegroundIntent() -> UInt64? {
        let requestRevision: UInt64
        if !foregroundRequested {
            foregroundRequested = true
            guard advanceIntentRevision() else { return nil }
            requestRevision = intentRevision
        } else if currentContext == nil, openingTask == nil, !isTransitionInProgress,
            case .failed = state
        {
            // 同一前台 intent 的并发调用共享一次 open；只有失败后的新显式调用才重试。
            guard advanceIntentRevision() else { return nil }
            requestRevision = intentRevision
        } else {
            requestRevision = intentRevision
        }
        return requestRevision
    }

    func fulfillForegroundIntent(_ requestRevision: UInt64) async {
        await ensureForeground(for: requestRevision)
    }

    func enterBackground() async {
        guard let backgroundRevision = captureBackgroundIntent() else { return }
        await fulfillBackgroundIntent(backgroundRevision)
    }

    /// callback 返回前先推进 revision、取消 opening 并公开 suspended；WSS teardown
    /// 由受跟踪的 scene worker 按 FIFO 调用 `fulfillBackgroundIntent` 完成。
    @discardableResult
    func captureBackgroundIntent() -> UInt64? {
        let backgroundRevision: UInt64
        if foregroundRequested {
            foregroundRequested = false
            guard advanceIntentRevision() else { return nil }
            backgroundRevision = intentRevision
        } else {
            backgroundRevision = intentRevision
        }
        state = .suspended
        openingTask?.cancel()
        return backgroundRevision
    }

    func fulfillBackgroundIntent(_ backgroundRevision: UInt64) async {
        while openingTask != nil || teardownInProgress || mutationInProgress {
            await waitForTransition()
        }
        if let context = currentContext {
            currentContext = nil
            currentGeneration = nil
            await teardown(context)
        }
        if intentRevision == backgroundRevision, !foregroundRequested {
            state = .suspended
        }
    }

    func reloadAfterPairedMachineMutation() async {
        await reloadAfterPairedMachineMutation(expectedGeneration: currentGeneration)
    }

    func makePairingViewModel(
        context: MobileSessionContext,
        generation: UInt64
    ) -> PairingViewModel {
        let exactManager = context.localPairedMachineManager
        let localStore = ClosureLocalPairedMachineManager { [weak self, exactManager] machineID in
            guard let self else {
                throw SessionSourceFailure(code: .storageUnavailable)
            }
            try await self.forgetLocalMachine(
                machineID: machineID,
                expectedGeneration: generation,
                manager: exactManager
            )
        }
        let viewModel = PairingViewModel(source: context.source, localStore: localStore)
        viewModel.onPaired = { [weak self] _ in
            Task { @MainActor in
                await self?.reloadAfterPairedMachineMutation(expectedGeneration: generation)
            }
        }
        return viewModel
    }

    private func ensureForeground(for requestRevision: UInt64) async {
        while foregroundRequested, intentRevision == requestRevision {
            if currentContext != nil { return }
            if openingTask != nil || teardownInProgress || mutationInProgress {
                await waitForTransition()
                continue
            }

            generation &+= 1
            guard generation != 0 else {
                foregroundRequested = false
                state = .failed(SessionSourceFailure(code: .securityError))
                resumeTransitionWaiters()
                return
            }
            let requestedGeneration = generation
            state = .starting(generation: requestedGeneration)
            let factory = factory
            let task = Task<MobileSessionContext, any Error> {
                try await factory.makeContext()
            }
            openingTask = task
            openingIntentRevision = requestRevision

            let result = await task.result
            guard openingIntentRevision == requestRevision else {
                // 只有创建 task 的 owner 会清理该槽位；走到这里表示内部状态损坏。
                if case .success(let context) = result {
                    await teardown(context)
                }
                state = .failed(SessionSourceFailure(code: .securityError))
                resumeTransitionWaiters()
                return
            }
            openingTask = nil
            openingIntentRevision = nil

            guard foregroundRequested, intentRevision == requestRevision else {
                if case .success(let staleContext) = result {
                    await teardown(staleContext)
                }
                if !foregroundRequested { state = .suspended }
                resumeTransitionWaiters()
                return
            }

            switch result {
            case .success(let context):
                currentContext = context
                currentGeneration = requestedGeneration
                startVerifiedRevocationMonitor(
                    context: context,
                    generation: requestedGeneration
                )
                state = .active(generation: requestedGeneration)
                onSourceReady?(context, requestedGeneration)
            case .failure(let error):
                state = .failed(Self.publicFailure(error))
            }
            resumeTransitionWaiters()
            return
        }
    }

    private func reloadAfterPairedMachineMutation(expectedGeneration: UInt64?) async {
        guard foregroundRequested else { return }
        if let expectedGeneration, currentGeneration != expectedGeneration {
            return
        }
        guard advanceIntentRevision() else { return }
        let mutationRevision = intentRevision
        mutationInProgress = true
        openingTask?.cancel()

        while openingTask != nil || teardownInProgress {
            await waitForTransition()
        }
        if let expectedGeneration, currentGeneration != expectedGeneration {
            mutationInProgress = false
            resumeTransitionWaiters()
            return
        }
        if let context = currentContext {
            currentContext = nil
            currentGeneration = nil
            await teardown(context)
        }
        mutationInProgress = false
        resumeTransitionWaiters()
        guard foregroundRequested, intentRevision == mutationRevision else { return }
        await ensureForeground(for: mutationRevision)
    }

    private func forgetLocalMachine(
        machineID: String,
        expectedGeneration: UInt64,
        manager: any LocalPairedMachineManaging
    ) async throws {
        guard foregroundRequested, currentGeneration == expectedGeneration,
            currentContext != nil, !mutationInProgress
        else {
            throw SessionSourceFailure(code: .securityError)
        }
        guard advanceIntentRevision() else {
            throw SessionSourceFailure(code: .securityError)
        }
        mutationInProgress = true
        let context = currentContext
        currentContext = nil
        currentGeneration = nil
        if let context { await teardown(context) }

        let deletionResult: Result<Void, any Error>
        do {
            try await manager.forgetLocal(machineID: machineID)
            deletionResult = .success(())
        } catch {
            deletionResult = .failure(error)
        }
        mutationInProgress = false
        resumeTransitionWaiters()

        switch deletionResult {
        case .success:
            if foregroundRequested {
                await ensureForeground(for: intentRevision)
            } else {
                state = .suspended
            }
        case .failure(let error):
            state = .failed(Self.publicFailure(error))
            throw error
        }
    }

    private func teardown(_ context: MobileSessionContext) async {
        precondition(!teardownInProgress)
        teardownInProgress = true
        let monitorTask = verifiedRevocationMonitorTask
        verifiedRevocationMonitorTask = nil
        verifiedRevocationMonitorGeneration = nil
        monitorTask?.cancel()
        await context.source.shutdown()
        await monitorTask?.value
        teardownInProgress = false
        resumeTransitionWaiters()
    }

    private func startVerifiedRevocationMonitor(
        context: MobileSessionContext,
        generation: UInt64
    ) {
        precondition(verifiedRevocationMonitorTask == nil)
        verifiedRevocationMonitorGeneration = generation
        let source = context.source
        let manager = context.localPairedMachineManager
        verifiedRevocationMonitorTask = Task { @MainActor [weak self, source, manager] in
            let stream = await source.machines()
            for await resource in stream {
                guard !Task.isCancelled else { return }
                guard let machineID = Self.firstVerifiedRevokedMachine(in: resource) else {
                    continue
                }
                guard let self,
                    self.currentGeneration == generation,
                    self.verifiedRevocationMonitorGeneration == generation
                else { return }

                // 让 monitor 自身先退出，再由独立 generation-bound operation 执行
                // teardown/delete/reopen，避免 teardown join 当前 monitor 形成自等待。
                Task { @MainActor [weak self, manager] in
                    guard let self else { return }
                    do {
                        try await self.forgetLocalMachine(
                            machineID: machineID,
                            expectedGeneration: generation,
                            manager: manager
                        )
                    } catch {
                        // `forgetLocalMachine` 已把 deletion failure 公开为 composition failed；
                        // stale/background generation 则由 guard 安静拒绝，下一次 cold-open 重试。
                    }
                }
                return
            }
        }
    }

    private static func firstVerifiedRevokedMachine(
        in resource: ResourceState<[MachineSummary]>
    ) -> String? {
        let machines: [MachineSummary]
        switch resource {
        case .loading(let previous):
            machines = previous ?? []
        case .ready(let value, _), .stale(let value, _):
            machines = value
        case .failed:
            machines = []
        }
        return machines.first(where: { $0.connectionState == .revoked })?.id
    }

    private var isTransitionInProgress: Bool {
        teardownInProgress || mutationInProgress
    }

    private func waitForTransition() async {
        await withCheckedContinuation { continuation in
            transitionWaiters.append(continuation)
        }
    }

    private func resumeTransitionWaiters() {
        let waiters = transitionWaiters
        transitionWaiters.removeAll(keepingCapacity: false)
        for waiter in waiters { waiter.resume() }
    }

    @discardableResult
    private func advanceIntentRevision() -> Bool {
        intentRevision &+= 1
        guard intentRevision != 0 else {
            foregroundRequested = false
            state = .failed(SessionSourceFailure(code: .securityError))
            openingTask?.cancel()
            resumeTransitionWaiters()
            return false
        }
        return true
    }

    private static func publicFailure(_ error: any Error) -> SessionSourceFailure {
        if let failure = error as? SessionSourceFailure { return failure }
        return SessionSourceFailure(code: .unknown)
    }
}

private struct ClosureLocalPairedMachineManager: LocalPairedMachineManaging {
    let operation: @Sendable (String) async throws -> Void

    func forgetLocal(machineID: String) async throws {
        try await operation(machineID)
    }
}

struct RelayMobileSessionSourceBuilder: MobileSessionSourceBuilding {
    let pairedMachineStore: PairedMachineStore

    func makeContext() async throws -> MobileSessionContext {
        let source = try await RelaySessionSource.open(
            scope: .allPairedMachines,
            pairedMachineStore: pairedMachineStore
        )
        do {
            // open 尚未开始 observation/network；此处 snapshot 与该 source generation 绑定。
            let records = try await pairedMachineStore.list()
            let manager = try PairedMachineLocalManager(
                store: pairedMachineStore,
                records: records
            )
            return MobileSessionContext(
                source: source,
                localPairedMachineManager: manager
            )
        } catch {
            await source.shutdown()
            throw error
        }
    }
}

extension CompositionRoot {
    static func production(fileManager: FileManager = .default) throws -> CompositionRoot {
        let storage = try MobileApplicationStorage.production(fileManager: fileManager)
        let pairedMachineStore = PairedMachineStore(
            keyStore: AppleKeychainStore(),
            stateRootURL: storage.stateRootURL,
            clientKind: .iOSApp,
            installationID: storage.installationID
        )
        return CompositionRoot(
            factory: RelayMobileSessionSourceBuilder(pairedMachineStore: pairedMachineStore)
        )
    }
}

/// 每代 source 的 exact paired-record snapshot。旧 generation 的 signed revoked terminal
/// 只能删除旧 record；即使同 machineID 已重新配对，也不会按 ID 查当前 record 后误删新 grant。
actor PairedMachineLocalManager: LocalPairedMachineManaging {
    private let store: PairedMachineStore
    private var recordsByMachineID: [String: StoredPairedMachineRecordV1]

    init(
        store: PairedMachineStore,
        records: [StoredPairedMachineRecordV1]
    ) throws {
        var indexed: [String: StoredPairedMachineRecordV1] = [:]
        for record in records {
            guard indexed.updateValue(record, forKey: record.machineID) == nil else {
                throw SessionSourceFailure(code: .securityError)
            }
        }
        self.store = store
        recordsByMachineID = indexed
    }

    func forgetLocal(machineID: String) async throws {
        guard let record = recordsByMachineID[machineID] else {
            throw SessionSourceFailure(code: .machineOffline)
        }
        try await store.deleteExact(record)
        let remaining = try await store.list()
        guard !remaining.contains(record) else {
            throw SessionSourceFailure(code: .storageUnavailable)
        }
        recordsByMachineID.removeValue(forKey: machineID)
    }
}

struct MobileApplicationStorage: Equatable {
    static let installationIDFileName = "installation-id.v1"
    static let stateDirectoryComponents = ["AgentDeck", "clients", "ios-app"]

    let stateRootURL: URL
    let installationID: UUID

    static func production(fileManager: FileManager = .default) throws -> Self {
        let applicationSupport = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        return try open(applicationSupportURL: applicationSupport, fileManager: fileManager)
    }

    static func open(
        applicationSupportURL: URL,
        fileManager: FileManager = .default
    ) throws -> Self {
        var root = applicationSupportURL.standardizedFileURL
        for component in stateDirectoryComponents {
            root.appendPathComponent(component, isDirectory: true)
        }
        do {
            try ensurePrivateDirectory(root, fileManager: fileManager)
            try excludeFromBackup(root)
            let installationURL = root.appendingPathComponent(
                installationIDFileName,
                isDirectory: false
            )
            let installationID = try loadOrCreateInstallationID(
                at: installationURL,
                fileManager: fileManager
            )
            return Self(stateRootURL: root, installationID: installationID)
        } catch let failure as SessionSourceFailure {
            throw failure
        } catch {
            throw SessionSourceFailure(code: .storageUnavailable)
        }
    }

    private static func ensurePrivateDirectory(
        _ url: URL,
        fileManager: FileManager
    ) throws {
        var isDirectory: ObjCBool = false
        if fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory) {
            let values = try url.resourceValues(forKeys: [
                .isDirectoryKey, .isSymbolicLinkKey,
            ])
            guard isDirectory.boolValue, values.isDirectory == true,
                values.isSymbolicLink != true
            else {
                throw SessionSourceFailure(code: .storageUnavailable)
            }
        } else {
            try fileManager.createDirectory(
                at: url,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        try fileManager.setAttributes(
            [
                .posixPermissions: 0o700,
                .protectionKey: FileProtectionType.complete,
            ],
            ofItemAtPath: url.path
        )
    }

    private static func loadOrCreateInstallationID(
        at url: URL,
        fileManager: FileManager
    ) throws -> UUID {
        let id: UUID
        if fileManager.fileExists(atPath: url.path) {
            id = try readInstallationID(at: url)
        } else {
            let generated = UUID()
            let bytes = Data((generated.uuidString.lowercased() + "\n").utf8)
            do {
                try bytes.write(
                    to: url,
                    // Foundation 明确不允许同时使用 `.atomic` 与
                    // `.withoutOverwriting`。这里优先守住 concurrent first-writer；
                    // 若进程在 37-byte 写入中止，残留记录会在下次启动 fail-close，
                    // 不会静默轮换 installation identity。
                    options: [.withoutOverwriting, .completeFileProtection]
                )
                id = generated
            } catch  where fileManager.fileExists(atPath: url.path) {
                id = try readInstallationID(at: url)
            }
        }

        try fileManager.setAttributes(
            [
                .posixPermissions: 0o600,
                .protectionKey: FileProtectionType.complete,
            ],
            ofItemAtPath: url.path
        )
        try excludeFromBackup(url)
        guard try readInstallationID(at: url) == id else {
            throw SessionSourceFailure(code: .storageUnavailable)
        }
        return id
    }

    private static func readInstallationID(at url: URL) throws -> UUID {
        let values = try url.resourceValues(forKeys: [
            .isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey,
        ])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
            values.fileSize == 37
        else {
            throw SessionSourceFailure(code: .storageUnavailable)
        }
        let bytes = try Data(contentsOf: url, options: .mappedIfSafe)
        guard bytes.count == 37,
            let string = String(data: bytes, encoding: .utf8),
            string.last == "\n",
            let parsed = UUID(uuidString: String(string.dropLast())),
            parsed.uuidString.lowercased() + "\n" == string,
            parsed != UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        else {
            throw SessionSourceFailure(code: .storageUnavailable)
        }
        return parsed
    }

    private static func excludeFromBackup(_ url: URL) throws {
        var mutableURL = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try mutableURL.setResourceValues(values)
        guard
            try url.resourceValues(forKeys: [.isExcludedFromBackupKey])
                .isExcludedFromBackup == true
        else {
            throw SessionSourceFailure(code: .storageUnavailable)
        }
    }
}

struct MobileLaunchOptions: Equatable {
    #if DEBUG
        static let fixtureArgument = "--agentdeck-fixture-source"
    #endif

    let pairInvite: String?
    let usesFixtureSource: Bool

    init(arguments: [String]) {
        #if DEBUG
            usesFixtureSource = arguments.contains(Self.fixtureArgument)
        #else
            // Fixture 是 preview/test 依赖，发行构建没有运行时降级入口。
            usesFixtureSource = false
        #endif
        guard
            let flagIndex = arguments.firstIndex(of: "--pair-invite"),
            arguments.indices.contains(flagIndex + 1)
        else {
            pairInvite = nil
            return
        }
        pairInvite = PairInviteInput.normalized(arguments[flagIndex + 1])
    }
}
