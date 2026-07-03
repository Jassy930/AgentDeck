import UIKit

/// Task 9 将覆写为完整实现；本任务仅提供最小占位供 MachineListViewController 编译。
final class SessionListViewController: UIViewController {
    private let source: MobileSessionSource
    private let machineID: String

    init(source: MobileSessionSource, machineID: String) {
        self.source = source
        self.machineID = machineID
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "会话列表"
        view.backgroundColor = DesignTokens.bg
    }
}
