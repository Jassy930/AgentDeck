import AgentDeckSessionSource
import UIKit

@MainActor
final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    private enum LifecycleIntent {
        case foreground(revision: UInt64)
        case background(revision: UInt64)
    }

    var window: UIWindow?
    private var compositionRoot: CompositionRoot?
    private var pendingPairInvite: String?
    private var lifecycleIntents: [LifecycleIntent] = []
    private var lifecycleWorker: Task<Void, Never>?

    override init() {
        super.init()
    }

    #if DEBUG
        init(testingCompositionRoot: CompositionRoot) {
            compositionRoot = testingCompositionRoot
            super.init()
        }

        func requestBackgroundForTesting() {
            requestBackground()
        }
    #endif

    func scene(
        _ scene: UIScene,
        willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        window.overrideUserInterfaceStyle = .dark
        window.rootViewController = statusController(
            title: "正在连接 AgentDeck…",
            subtitle: "正在载入本机配对身份"
        )
        window.makeKeyAndVisible()
        self.window = window

        let launchOptions = MobileLaunchOptions(arguments: ProcessInfo.processInfo.arguments)
        pendingPairInvite = launchOptions.pairInvite

        #if DEBUG
            if launchOptions.usesFixtureSource {
                installFixtureSource()
                return
            }
        #endif

        do {
            let root = try CompositionRoot.production()
            compositionRoot = root
            root.onStateChange = { [weak self, weak root] state in
                guard let self, self.compositionRoot === root else { return }
                self.renderCompositionState(state)
            }
            root.onSourceReady = { [weak self, weak root] context, generation in
                guard let self, let root, self.compositionRoot === root else { return }
                self.installProductionContext(
                    context,
                    generation: generation,
                    root: root
                )
            }
            requestForeground()
        } catch {
            renderCompositionFailure(Self.publicFailure(error))
        }
    }

    func sceneWillEnterForeground(_ scene: UIScene) {
        _ = scene
        requestForeground()
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
        _ = scene
        requestBackground()
    }

    func sceneDidDisconnect(_ scene: UIScene) {
        _ = scene
        requestBackground()
    }

    private func requestForeground() {
        guard let compositionRoot,
            let revision = compositionRoot.captureForegroundIntent()
        else { return }
        enqueueLifecycleIntent(.foreground(revision: revision), root: compositionRoot)
    }

    private func requestBackground() {
        guard let compositionRoot,
            let revision = compositionRoot.captureBackgroundIntent()
        else { return }
        enqueueLifecycleIntent(.background(revision: revision), root: compositionRoot)
    }

    private func enqueueLifecycleIntent(
        _ intent: LifecycleIntent,
        root: CompositionRoot
    ) {
        lifecycleIntents.append(intent)
        guard lifecycleWorker == nil else { return }
        // Task 与 self 暂时形成有界闭环，确保 scene disconnect 后 UIKit 即使释放
        // delegate，已同步 capture 的 background intent 仍会完成 shutdown/join。
        // `drainLifecycleIntents` 末尾清空 lifecycleWorker，队列耗尽后立即断环。
        lifecycleWorker = Task { @MainActor [self, root] in
            await drainLifecycleIntents(root: root)
        }
    }

    private func drainLifecycleIntents(root: CompositionRoot) async {
        while compositionRoot === root, !lifecycleIntents.isEmpty {
            let intent = lifecycleIntents.removeFirst()
            switch intent {
            case .foreground(let revision):
                await root.fulfillForegroundIntent(revision)
            case .background(let revision):
                await root.fulfillBackgroundIntent(revision)
            }
        }
        lifecycleWorker = nil
        if compositionRoot !== root {
            lifecycleIntents.removeAll(keepingCapacity: false)
        }
    }

    private func installProductionContext(
        _ context: MobileSessionContext,
        generation: UInt64,
        root: CompositionRoot
    ) {
        let initialInvite = pendingPairInvite
        pendingPairInvite = nil
        let machineList = MachineListViewController(
            source: context.source,
            pairingViewModelFactory: { [context, root] _ in
                root.makePairingViewModel(context: context, generation: generation)
            },
            initialPairInvite: initialInvite
        )
        window?.rootViewController = UINavigationController(rootViewController: machineList)
    }

    #if DEBUG
        private func installFixtureSource() {
            let source = FixtureSessionSource()
            let machineList = MachineListViewController(
                source: source,
                pairingViewModelFactory: { PairingViewModel(source: $0) },
                initialPairInvite: pendingPairInvite
            )
            pendingPairInvite = nil
            window?.rootViewController = UINavigationController(rootViewController: machineList)
        }
    #endif

    private func renderCompositionState(_ state: MobileCompositionState) {
        switch state {
        case .idle, .starting:
            window?.rootViewController = statusController(
                title: "正在连接 AgentDeck…",
                subtitle: "正在恢复已配对机器的加密会话"
            )
        case .failed(let failure):
            renderCompositionFailure(failure)
        case .active, .suspended:
            break
        }
    }

    private func renderCompositionFailure(_ failure: SessionSourceFailure) {
        window?.rootViewController = statusController(
            title: "无法启动 Companion",
            subtitle: failure.message ?? failure.code.rawValue
        )
    }

    private func statusController(title: String, subtitle: String?) -> UIViewController {
        let controller = UIViewController()
        controller.view.backgroundColor = DesignTokens.bg
        let status = MobileEmptyStateView(title: title, subtitle: subtitle)
        status.translatesAutoresizingMaskIntoConstraints = false
        controller.view.addSubview(status)
        NSLayoutConstraint.activate([
            status.leadingAnchor.constraint(equalTo: controller.view.leadingAnchor),
            status.trailingAnchor.constraint(equalTo: controller.view.trailingAnchor),
            status.topAnchor.constraint(equalTo: controller.view.topAnchor),
            status.bottomAnchor.constraint(equalTo: controller.view.bottomAnchor),
        ])
        return controller
    }

    private static func publicFailure(_ error: any Error) -> SessionSourceFailure {
        if let failure = error as? SessionSourceFailure { return failure }
        return SessionSourceFailure(code: .unknown)
    }
}
