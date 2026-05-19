import Foundation

// AgentDeck — Step 1 entry point.
//
// Step 1 proves three things before any UI exists:
//   1. The Swift app can spawn agentdeckd as a child process.
//   2. The neutral JSONL IPC round trip works (ping → pong).
//   3. The A1 lifecycle contract holds: the daemon dies when the app exits.
//
// The SwiftUI window (Beat 1 — the only user-perceivable wow) lands in
// Step 4. Keeping Step 1 headless makes the IPC + lifecycle contract
// testable in CI without a windowing session.

let client = DaemonClient()

do {
    try client.start()
    print("agentdeckd spawned.")

    let pong = try client.roundTrip(IpcMessage(kind: "ping", id: 1, payload: nil))
    guard pong.kind == "pong", pong.id == 1 else {
        FileHandle.standardError.write(Data("unexpected reply: \(pong)\n".utf8))
        client.shutdown()
        exit(1)
    }
    print("IPC round trip OK: ping → pong (id 1).")

    client.shutdown()
    print("daemon shut down. A1 lifecycle: clean.")
    exit(0)
} catch {
    FileHandle.standardError.write(Data("FATAL: \(error)\n".utf8))
    client.shutdown()
    exit(1)
}
