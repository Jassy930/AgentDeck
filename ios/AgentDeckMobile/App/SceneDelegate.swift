import UIKit

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(
        _ scene: UIScene,
        willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        // Task 8 起替换为 MachineListViewController(source: FixtureSessionSource())
        window.rootViewController = UINavigationController(rootViewController: PlaceholderViewController())
        window.makeKeyAndVisible()
        self.window = window
    }
}
