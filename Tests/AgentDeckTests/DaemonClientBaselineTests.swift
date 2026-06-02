import Foundation
import Testing
@testable import AgentDeck

// B1 baseline regression snapshot for `DaemonClient` and its helpers.
//
// Purpose: lock in a handful of externally-observable behaviors of the current
// `DaemonClient` BEFORE the B2-B5 refactor (which extracts `DaemonTransport`
// and introduces `ProcessDaemonTransport` / `StubDaemonTransport`). If the
// refactor accidentally drifts the request-id allocator semantics, the
// daemon-environment override policy, or the malformed-line fan-out, these
// tests fail and surface the regression at the seam — without spawning a real
// daemon binary.
//
// Each test pins one behavior that the existing `IpcTests.swift` suites do
// NOT already assert directly (they cover `.dev` profile + non-empty base,
// `prepareRoundTripRequest` preserving an explicit id, and router happy-path
// routing of replies/session-events).

@Suite("DaemonClient baseline (B1 snapshot)")
struct DaemonClientBaselineTests {

    @Test("daemonEnvironment assigns AGENTDECK_PROFILE=stable when base env is empty")
    func daemonEnvironmentAssignsStableProfileWhenBaseIsEmpty() {
        let env = DaemonClient.daemonEnvironment(profile: .stable, base: [:])

        #expect(env["AGENTDECK_PROFILE"] == "stable")
        #expect(env.count == 1)
    }

    @Test("daemonEnvironment overrides AGENTDECK_PROFILE already present in base env")
    func daemonEnvironmentOverridesAgentdeckProfileAlreadyInBase() {
        let env = DaemonClient.daemonEnvironment(
            profile: .dev,
            base: [
                "PATH": "/usr/bin",
                "AGENTDECK_PROFILE": "stable",
            ]
        )

        // Policy: the profile argument is authoritative — it always overrides
        // whatever the inherited environment carried. A future refactor that
        // changes this to "merge if absent" would silently launch the daemon
        // under the wrong profile, so this test pins the override semantics.
        #expect(env["AGENTDECK_PROFILE"] == "dev")
        #expect(env["PATH"] == "/usr/bin")
    }

    @Test("DaemonRequestIdAllocator assigns strictly increasing ids starting at the configured value")
    func requestIdAllocatorAssignsStrictlyIncreasingIdsStartingAtConfiguredValue() {
        let allocator = DaemonRequestIdAllocator(startingAt: 7)

        let first = allocator.assignUniqueId(to: IpcMessage(kind: "alpha", sessionId: "s1"))
        let second = allocator.assignUniqueId(to: IpcMessage(kind: "beta"))
        let third = allocator.assignUniqueId(to: IpcMessage(kind: "gamma"))

        #expect(first.id == 7)
        #expect(second.id == 8)
        #expect(third.id == 9)
        // Allocator must only touch `id` — other fields stay untouched so the
        // caller can build the rest of the IpcMessage independently.
        #expect(first.kind == "alpha")
        #expect(first.sessionId == "s1")
        #expect(second.kind == "beta")
        #expect(third.kind == "gamma")
    }

    @Test("router routes malformed line as error reply to every pending id and clears them")
    func routerRoutesMalformedLineAsErrorReplyToEveryPendingIdAndClearsThem() {
        let router = DaemonMessageRouter()

        #expect(router.registerPending(id: 10))
        #expect(router.registerPending(id: 11))

        router.routeMalformedLine("oops")

        let firstReply = router.takeReply(id: 10)
        let secondReply = router.takeReply(id: 11)

        #expect(firstReply?.kind == "error")
        #expect(firstReply?.id == 10)
        #expect(secondReply?.kind == "error")
        #expect(secondReply?.id == 11)

        // After fan-out the ids are no longer pending — re-registering must
        // succeed, which would not be the case if `routeMalformedLine` left
        // the pending set untouched.
        #expect(router.registerPending(id: 10))
        #expect(router.registerPending(id: 11))
    }
}
