import Foundation

struct AgentItemStore {
    var items: [UIItem] = []
    var itemIndexById: [String: Int] = [:]
}

enum AgentItemReducer {
    static func upsert(_ d: [String: Any], into store: inout AgentItemStore) {
        guard let id = d["id"] as? String,
              let kind = d["kind"] as? String,
              let life = d["lifecycle"] as? String else { return }

        var item = store.itemIndexById[id].flatMap { idx in
            store.items.indices.contains(idx) ? store.items[idx] : nil
        } ?? UIItem(id: id, lifecycle: life, kind: kind)
        item.lifecycle = life
        item.kind = kind

        switch kind {
        case "user", "message", "reasoning":
            let t = d["text"] as? String ?? ""
            if life == "delta" {
                item.text.append(contentsOf: t)
                item.textBuffer.append(t)
                item.hasNonWhitespaceText = item.hasNonWhitespaceText || agentDeckContainsNonWhitespace(t)
            } else if !t.isEmpty {
                item.text = t
                item.textBuffer.replace(with: t)
                item.hasNonWhitespaceText = agentDeckContainsNonWhitespace(t)
            }
        case "shell":
            item.command = d["command"] as? String ?? item.command
            if let o = d["output"] as? String {
                if life == "delta" {
                    item.output.append(contentsOf: o)
                    item.outputBuffer.append(o)
                } else {
                    item.output = o
                    item.outputBuffer.replace(with: o)
                }
            }
            item.exitCode = d["exitCode"] as? Int ?? item.exitCode
            item.cwdText = d["cwd"] as? String ?? item.cwdText
            item.statusName = d["status"] as? String ?? item.statusName
            item.durationMs = d["durationMs"] as? Int ?? item.durationMs
            item.sourceName = d["source"] as? String ?? item.sourceName
            item.processId = d["processId"] as? String ?? item.processId
        case "fileEdit":
            item.path = d["path"] as? String ?? item.path
            if let diff = d["diff"] as? String {
                item.diff = diff
                item.diffBuffer.replace(with: diff)
            }
            item.statusName = d["status"] as? String ?? item.statusName
        case "webSearch":
            item.query = d["query"] as? String ?? item.query
            item.action = d["action"] as? String ?? item.action
            item.actionQuery = d["actionQuery"] as? String ?? item.actionQuery
            item.queries = agentDeckStringArray(from: d["queries"]) ?? item.queries
            item.url = d["url"] as? String ?? item.url
            item.pattern = d["pattern"] as? String ?? item.pattern
        case "plan", "reviewMode":
            item.text = d["text"] as? String ?? item.text
            item.review = d["review"] as? String ?? item.review
            item.action = d["action"] as? String ?? item.action
        case "toolCall":
            item.toolKind = d["toolKind"] as? String ?? item.toolKind
            item.server = d["server"] as? String ?? item.server
            item.namespace = d["namespace"] as? String ?? item.namespace
            item.tool = d["tool"] as? String ?? item.tool
            item.statusName = d["status"] as? String ?? item.statusName
            item.arguments = d["arguments"] as? String ?? item.arguments
            item.result = d["result"] as? String ?? item.result
            item.errorText = d["error"] as? String ?? item.errorText
            item.durationMs = d["durationMs"] as? Int ?? item.durationMs
            item.success = d["success"] as? Bool ?? item.success
            item.resourceUri = d["resourceUri"] as? String ?? item.resourceUri
        case "collabAgentToolCall":
            item.tool = d["tool"] as? String ?? item.tool
            item.statusName = d["status"] as? String ?? item.statusName
            item.prompt = d["prompt"] as? String ?? item.prompt
            item.model = d["model"] as? String ?? item.model
            item.reasoningEffort = d["reasoningEffort"] as? String ?? item.reasoningEffort
            item.senderThreadId = d["senderThreadId"] as? String ?? item.senderThreadId
            item.receiverThreadIds = agentDeckStringArray(from: d["receiverThreadIds"]) ?? item.receiverThreadIds
            item.agentsStates = d["agentsStates"] as? String ?? item.agentsStates
        case "media":
            item.mediaKind = d["mediaKind"] as? String ?? item.mediaKind
            item.path = d["path"] as? String ?? item.path
            item.statusName = d["status"] as? String ?? item.statusName
            item.result = d["result"] as? String ?? item.result
            item.revisedPrompt = d["revisedPrompt"] as? String ?? item.revisedPrompt
            item.savedPath = d["savedPath"] as? String ?? item.savedPath
        case "raw":
            item.descriptionText = d["description"] as? String ?? ""
        default:
            break
        }

        if let idx = store.itemIndexById[id], store.items.indices.contains(idx) {
            store.items[idx] = item
        } else {
            store.itemIndexById[item.id] = store.items.count
            store.items.append(item)
        }
    }
}
