// 生成物 · 由设计系统 SSOT 生成（designs/agentdeck-design-system/components/components.json）。
// 禁止手改；改 SSOT 后在 designs/agentdeck-design-system 跑 `node tools/build.mjs` 重生成。

/// 组件稳定视觉骨架契约：设计自有的静态标签与禁止元素（不含行为、不含 fixture 数据）。
enum ComponentSpecs {
    struct Spec {
        let key: String
        let title: String
        let requiredLabels: [String]
        let forbiddenLabels: [String]
        let forbidAccentBar: Bool
    }

    static let all: [Spec] = [
        Spec(
            key: "m-user",
            title: "用户气泡 · m-user",
            requiredLabels: [],
            forbiddenLabels: ["You"],
            forbidAccentBar: true
        ),
        Spec(
            key: "envpanel",
            title: "环境面板 · envpanel",
            requiredLabels: ["变更 Changes", "Git", "分支", "提交"],
            forbiddenLabels: ["环境信息", "提交或推送", "暂无来源"],
            forbidAccentBar: false
        ),
        Spec(
            key: "composer",
            title: "输入栏 · composer",
            requiredLabels: ["继续对话，或 @ 引用文件…"],
            forbiddenLabels: [],
            forbidAccentBar: false
        ),
    ]

    static func spec(_ key: String) -> Spec? { all.first { $0.key == key } }
}
