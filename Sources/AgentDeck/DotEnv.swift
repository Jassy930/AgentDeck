import Foundation

/// 极简 `.env` 加载：`KEY=VALUE` 逐行，跳过空行与 `#` 注释，支持 `export ` 前缀与
/// 包裹引号。不引第三方依赖。纯解析与副作用（`setenv`）分离，便于单测。
///
/// 优先级：真实进程环境优先——`.env` 只填补**未设**的键，绝不覆盖 shell 里 export
/// 或命令行内联的值。注入后 daemon 子进程也能读到（其环境继承自本进程）。
enum DotEnv {

    /// 纯函数：把 `.env` 文本解析为有序键值对。无效行（无 `=` / 空键）跳过。
    static func parse(_ contents: String) -> [(key: String, value: String)] {
        var out: [(key: String, value: String)] = []
        for rawLine in contents.split(separator: "\n", omittingEmptySubsequences: false) {
            var line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("export ") {
                line = String(line.dropFirst("export ".count)).trimmingCharacters(in: .whitespaces)
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { continue }
            let value = stripQuotes(String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces))
            out.append((key, value))
        }
        return out
    }

    /// 去掉成对的首尾引号（`"..."` 或 `'...'`）。
    private static func stripQuotes(_ s: String) -> String {
        guard s.count >= 2, let first = s.first, let last = s.last else { return s }
        if (first == "\"" && last == "\"") || (first == "'" && last == "'") {
            return String(s.dropFirst().dropLast())
        }
        return s
    }

    /// 解析 `contents` 并把**未在 `existing` 中**的键写入环境。返回注入的键数。
    /// `setValue` 默认用 `setenv(_,_,0)`（overwrite=0：不覆盖已存在），side effect 可注入以便单测。
    @discardableResult
    static func inject(
        _ contents: String,
        existing: [String: String],
        setValue: (String, String) -> Void
    ) -> Int {
        var injected = 0
        for (key, value) in parse(contents) where existing[key] == nil {
            setValue(key, value)
            injected += 1
        }
        return injected
    }

    /// 从当前工作目录加载 `.env`（若存在）。`swift run` 时 CWD 即仓库根。
    /// 不存在或读失败即静默返回 0。返回注入的键数。
    @discardableResult
    static func loadDefault() -> Int {
        let path = FileManager.default.currentDirectoryPath + "/.env"
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else { return 0 }
        return inject(
            contents,
            existing: ProcessInfo.processInfo.environment,
            setValue: { key, value in setenv(key, value, 0) }
        )
    }
}
