import AppKit
import AgentDeckCore

/// 一个设计系统组件样本：key（稳定标识，对应 components.json 的组件 key）、
/// 标题、以及用固定 fixture 配置好的真实组件视图。
/// 既供 `--gallery` 目视 QA，也供结构断言测试消费。
struct GallerySpecimen {
    let key: String
    let title: String
    let view: NSView
}

/// 组件画廊：隔离渲染每个设计系统组件。复用预览的 fixture 与真实组件，
/// 不引入任何专供画廊的“假”渲染路径——画廊里看到的就是生产组件。
enum GalleryBootstrap {
    /// 画廊/断言统一使用的会话行宽（真实转录宽度）。
    static let specimenWidth: CGFloat = 900

    @MainActor
    static func specimens() -> [GallerySpecimen] {
        var out: [GallerySpecimen] = []

        // 用户气泡（对齐后：纯灰气泡、无 You 标签/边条）
        out.append(GallerySpecimen(
            key: "m-user",
            title: "用户气泡 · m-user",
            view: cell(for: userRow(), model: fixtureModel())))

        // reasoning cell
        out.append(GallerySpecimen(
            key: "reasoning",
            title: "推理 · reasoning",
            view: cell(for: assistantRow(reasoningItem()), model: fixtureModel())))

        // shell cell
        out.append(GallerySpecimen(
            key: "shell",
            title: "命令 · shell",
            view: cell(for: assistantRow(shellItem()), model: fixtureModel())))

        // diff / fileEdit cell
        out.append(GallerySpecimen(
            key: "fileEdit",
            title: "变更 · fileEdit",
            view: cell(for: assistantRow(diffItem()), model: fixtureModel())))

        // 环境面板（对齐后：只读 Changes/Git）
        let envModel = fixtureModel()
        envModel.environmentInfo = MockDaemonScript.environmentInfo
        out.append(GallerySpecimen(
            key: "envpanel",
            title: "环境面板 · envpanel",
            view: CodexEnvironmentPanelView(model: envModel)))

        // composer 输入栏
        out.append(GallerySpecimen(
            key: "composer",
            title: "输入栏 · composer",
            view: InputBarView(model: fixtureModel())))

        return out
    }

    // MARK: - Fixtures

    @MainActor
    private static func fixtureModel() -> SessionModel {
        SessionModel(turnStarter: NoopRuntimeTurnStarter())
    }

    @MainActor
    private static func cell(for row: ConversationDisplayRow, model: SessionModel) -> NSView {
        let cell = ConversationRowFactory.makeCell(for: row)
        if let conv = cell as? ConversationRowCellView {
            conv.configure(row: row, width: specimenWidth, model: model)
        }
        return cell
    }

    private static func userRow() -> ConversationDisplayRow {
        let item = UIItem(id: "g-user", lifecycle: "completed", kind: "user",
                          text: "把登录模块拆分成独立的 auth service，抽出 token 刷新逻辑，并补齐单元测试。")
        return ConversationDisplayRow(role: .userPrompt, turnId: "g-turn", item: item,
                                      firstInTurn: true, lastInTurn: false)
    }

    private static func assistantRow(_ item: UIItem) -> ConversationDisplayRow {
        ConversationDisplayRow(role: .assistantItem, turnId: "g-turn", item: item,
                               firstInTurn: false, lastInTurn: true)
    }

    private static func reasoningItem() -> UIItem {
        UIItem(id: "g-reason", lifecycle: "completed", kind: "reasoning",
               text: "先梳理 auth 目录下的依赖关系，确认哪些函数被外部引用，再决定拆分边界。")
    }

    private static func shellItem() -> UIItem {
        var s = UIItem(id: "g-shell", lifecycle: "completed", kind: "shell")
        s.command = "rg \"login\" src/ -l"
        s.output = "src/auth/login.ts\nsrc/auth/service.ts\nsrc/api/session.ts"
        s.outputBuffer.replace(with: s.output)
        s.exitCode = 0
        return s
    }

    private static func diffItem() -> UIItem {
        var d = UIItem(id: "g-diff", lifecycle: "completed", kind: "fileEdit")
        d.path = "auth/service.ts"
        d.statusName = "modified"
        d.diff = "@@ +64 -12 @@\n+ export class AuthService {}\n"
        d.diffBuffer.replace(with: d.diff)
        return d
    }
}

/// 画廊视图控制器：竖排每个组件样本（标题 + 组件），便于目视对照 showcase。
@MainActor
final class GalleryViewController: NSViewController {
    override func loadView() {
        let root = NSView()
        root.wantsLayer = true
        root.layer?.backgroundColor = CodexDesktopChrome.windowBackground.cgColor

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 28
        stack.edgeInsets = NSEdgeInsets(top: 32, left: 32, bottom: 32, right: 32)
        stack.translatesAutoresizingMaskIntoConstraints = false

        for specimen in GalleryBootstrap.specimens() {
            let title = NSTextField(labelWithString: specimen.title)
            title.font = .systemFont(ofSize: 12, weight: .medium)
            title.textColor = DesignTokens.text2
            title.translatesAutoresizingMaskIntoConstraints = false

            specimen.view.translatesAutoresizingMaskIntoConstraints = false
            specimen.view.widthAnchor.constraint(equalToConstant: GalleryBootstrap.specimenWidth).isActive = true

            let group = NSStackView(views: [title, specimen.view])
            group.orientation = .vertical
            group.alignment = .leading
            group.spacing = 8
            stack.addArrangedSubview(group)
        }

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        let doc = NSView()
        doc.translatesAutoresizingMaskIntoConstraints = false
        doc.addSubview(stack)
        scroll.documentView = doc
        root.addSubview(scroll)

        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: root.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            stack.topAnchor.constraint(equalTo: doc.topAnchor),
            stack.leadingAnchor.constraint(equalTo: doc.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: doc.trailingAnchor),
            stack.bottomAnchor.constraint(equalTo: doc.bottomAnchor),
            doc.widthAnchor.constraint(equalToConstant: GalleryBootstrap.specimenWidth + 64),
        ])

        self.view = root
    }
}
