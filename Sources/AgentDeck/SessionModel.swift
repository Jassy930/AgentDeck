import Foundation
import Observation

/// A neutral agent item as the UI sees it. Mirrors the daemon's AgentItem
/// (Eng D4 per-kind). The Swift app NEVER parses vendor formats — it only
/// ever decodes this neutral shape (Eng D2). Adding a Claude Code adapter
/// later changes nothing here.
struct UIItem: Identifiable {
    let id: String
    var lifecycle: String          // started | delta | completed
    var kind: String               // reasoning | shell | fileEdit | raw
    // Per-kind fields (only the relevant ones are populated).
    var text: String = ""          // reasoning
    var command: String = ""       // shell
    var output: String = ""        // shell
    var exitCode: Int?             // shell
    var path: String = ""          // fileEdit
    var diff: String = ""          // fileEdit
    var descriptionText: String = "" // raw (neutralized unknown)
}

/// The session view model. `@MainActor` + `@Observable`: every mutation is
/// main-thread (Eng C-uitest), SwiftUI observes it directly.
///
/// `state` is a MIRROR of the daemon's session state machine (Eng D9). The
/// daemon is the sole source of truth; this never invents a transition, it
/// only reflects `sessionState` messages. `statusText` drives the D6
/// transition copy ("Connecting to Codex…" etc).
@MainActor
@Observable
final class SessionModel {
    enum Phase: String {
        case idle, starting, ready, running, waitingApproval, draining, failed, closed
    }

    /// The chosen project directory (Eng D3: Swift validates before the
    /// daemon's authoritative check). nil → show the empty state (D5).
    var cwd: URL?
    var phase: Phase = .idle
    var items: [UIItem] = []
    var errorMessage: String?
    /// Prompts queued while a turn runs (Eng I1). v0.1: enqueue, auto-send
    /// on turn completion. Step 5 wires the auto-send; Step 4 shows the count.
    var queuedPrompts: [String] = []

    private let client = DaemonClient()
    private var daemonStarted = false

    /// D6 transition copy: reuse the D9 state machine, not a generic spinner.
    var statusText: String {
        switch phase {
        case .idle: return "Ready"
        case .starting: return "Connecting to Codex…"
        case .ready: return "Ready"
        case .running: return "Codex is working…"
        case .waitingApproval: return "Waiting for your approval"
        case .draining: return "Finishing up…"
        case .failed: return "Failed"
        case .closed: return "Closed"
        }
    }

    /// Eng D3: Swift-side cwd validation (existence/readability) — closest to
    /// the user, fastest feedback. The daemon does the authoritative final
    /// check before app-server.
    func chooseCwd(_ url: URL) -> String? {
        var isDir: ObjCBool = false
        let ok = FileManager.default.fileExists(
            atPath: url.path, isDirectory: &isDir)
        guard ok, isDir.boolValue else {
            return "Not a directory: \(url.path)"
        }
        guard FileManager.default.isReadableFile(atPath: url.path) else {
            return "Directory is not readable: \(url.path)"
        }
        cwd = url
        return nil
    }

    func submit(_ prompt: String) {
        let trimmed = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let cwd else { return }

        // Eng I1: a turn in flight → enqueue, don't drop, don't interrupt.
        if phase == .running || phase == .starting || phase == .waitingApproval {
            queuedPrompts.append(trimmed)
            return
        }

        if !daemonStarted {
            do {
                try client.start()
                daemonStarted = true
            } catch {
                phase = .failed
                errorMessage = "\(error)"
                return
            }
        }

        items.append(UIItem(id: "user-\(UUID().uuidString)",
                             lifecycle: "completed", kind: "user", text: trimmed))
        errorMessage = nil
        phase = .starting

        client.startSession(cwd: cwd.path, prompt: trimmed) { [weak self] raw in
            // Decode ON the main actor (the line crossed threads as a plain
            // String — Sendable). No non-Sendable value ever raced.
            guard let self else { return }
            let msg = (try? JSONDecoder().decode(
                IpcMessage.self, from: Data(raw.utf8)))
                ?? IpcMessage(kind: "error", id: nil,
                    payload: AnyCodable(["message": "malformed reply"]))
            self.handle(msg)
        }
    }

    private func handle(_ msg: IpcMessage) {
        switch msg.kind {
        case "sessionState":
            if let s = (msg.payload?.value as? [String: Any])?["state"] as? String,
               let p = Phase(rawValue: s) {
                phase = p
            }
        case "agentItem":
            if let dict = msg.payload?.value as? [String: Any] {
                upsert(dict)
            }
        case "turnComplete":
            phase = .ready
            drainQueueIfPossible()
        case "error":
            let m = (msg.payload?.value as? [String: Any])?["message"] as? String
            errorMessage = m ?? "unknown error"
            phase = .failed
        default:
            break
        }
    }

    /// Merge a streamed item by id: started creates, delta appends, completed
    /// finalizes. The daemon already coalesced deltas (Eng A2), so this stays
    /// simple.
    private func upsert(_ d: [String: Any]) {
        guard let id = d["id"] as? String,
              let kind = d["kind"] as? String,
              let life = d["lifecycle"] as? String else { return }

        var item = items.first(where: { $0.id == id })
            ?? UIItem(id: id, lifecycle: life, kind: kind)
        item.lifecycle = life
        item.kind = kind
        switch kind {
        case "reasoning":
            let t = d["text"] as? String ?? ""
            item.text = (life == "delta") ? item.text + t : t
        case "shell":
            item.command = d["command"] as? String ?? item.command
            if let o = d["output"] as? String {
                item.output = (life == "delta") ? item.output + o : o
            }
            item.exitCode = d["exitCode"] as? Int ?? item.exitCode
        case "fileEdit":
            item.path = d["path"] as? String ?? item.path
            item.diff = d["diff"] as? String ?? item.diff
        case "raw":
            item.descriptionText = d["description"] as? String ?? ""
        default:
            break
        }

        if let idx = items.firstIndex(where: { $0.id == id }) {
            items[idx] = item
        } else {
            items.append(item)
        }
    }

    private func drainQueueIfPossible() {
        guard !queuedPrompts.isEmpty, phase == .ready else { return }
        let next = queuedPrompts.removeFirst()
        submit(next)
    }

    func teardown() {
        client.shutdown()
    }
}
