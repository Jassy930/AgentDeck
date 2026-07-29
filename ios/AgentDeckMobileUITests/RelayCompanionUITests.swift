import Foundation
import XCTest

/// R4 fixed-topology 的首个真实 UI 契约。
///
/// Xcode 只把 invite 放入 fresh UI-test bundle；测试立即复制到自身 sandbox 的 mode 0600
/// 临时文件并删除，再复用 production `--pair-invite` 入口启动 App。没有显式 harness
/// 输入时必须 RED，不能退回 fixture。
final class RelayCompanionUITests: XCTestCase {
    private static let invitePathEnvironment = "AGENTDECK_RELAY_E2E_INVITE_PATH"
    private static let inviteResourceName = "RelayCompanionPairInvite"
    private static let lifecycleFenceName = "RelayCompanionBusinessObserved.fence"
    private static let conversationTitle = "R4.3 synthetic Codex"
    private static let promptSentinel = "R4.3 UI prompt sentinel"
    private static let restartMarkerTitle = "R4.4 daemon restart marker"
    private static let businessReadyUIWait: TimeInterval = 120

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    func testPairingReachesLocalConfirmation() throws {
        let app = try launchPairingApp()
        try beginPairing(in: app)
        waitForPairingWaiting(in: app)
    }

    func testPairListOpenPromptApproval() throws {
        let app = try launchPairingApp()
        try beginPairing(in: app)
        try openOriginalConversation(in: app)
        exercisePromptAndApproval(in: app)
    }

    func testFullLifecycleReconnectAndRevoke() throws {
        let app = try launchPairingApp()
        try beginPairing(in: app)
        try openOriginalConversation(in: app)
        exercisePromptAndApproval(in: app)
        try signalLifecycleFence()

        navigateBack(in: app)
        let restartMarker = app.staticTexts[Self.restartMarkerTitle]
        guard restartMarker.waitForExistence(timeout: 120) else {
            let originalTitleRemains = app.staticTexts[Self.conversationTitle].exists
            navigateBack(in: app)
            let machine = app.collectionViews["machines.list"].cells.firstMatch
            let machineState = machine.waitForExistence(timeout: 5) ? machine.label : "absent"
            XCTFail(
                "真实 daemon 重启后未向现有 production client 发布 catalog marker；"
                    + "originalTitleRemains=\(originalTitleRemains) machineState=\(machineState)"
            )
            return
        }

        app.terminate()
        app.launchArguments = []
        app.launch()
        try openConversation(titled: Self.restartMarkerTitle, in: app)
        XCTAssertTrue(
            app.staticTexts["synthetic Codex response"].waitForExistence(timeout: 90),
            "无 invite 冷启动后未恢复已提交 assistant history"
        )
        let approvalState = app.staticTexts["session.approval.state"]
        XCTAssertTrue(approvalState.waitForExistence(timeout: 60))
        let applied = NSPredicate(
            format: "label CONTAINS %@ AND label CONTAINS %@", "批准", "已应用")
        expectation(for: applied, evaluatedWith: approvalState)
        waitForExpectations(timeout: 60)

        navigateBack(in: app)
        navigateBack(in: app)
        let pairingButton = app.buttons["machines.pair"]
        XCTAssertTrue(pairingButton.waitForExistence(timeout: 30))
        pairingButton.tap()

        let pairedMachines = app.tables["pairing.paired-machines"]
        XCTAssertTrue(pairedMachines.waitForExistence(timeout: 30))
        let pairedMachine = pairedMachines.cells.firstMatch
        XCTAssertTrue(pairedMachine.waitForExistence(timeout: 30))
        pairedMachine.swipeLeft()
        let revoke = app.buttons["在线撤销"]
        XCTAssertTrue(revoke.waitForExistence(timeout: 15))
        revoke.tap()
        let confirmation = app.alerts.firstMatch
        XCTAssertTrue(confirmation.waitForExistence(timeout: 15))
        confirmation.buttons["撤销授权"].tap()

        XCTAssertTrue(
            app.staticTexts["还没有机器"].waitForExistence(timeout: 120),
            "verified revoke terminal 后本机 paired material 未被 production composition 清理"
        )
    }

    private func launchPairingApp() throws -> XCUIApplication {
        let invite = try loadPrivateInvite()
        let app = XCUIApplication()
        app.launchArguments = ["--pair-invite", invite]
        app.launch()
        return app
    }

    private func beginPairing(in app: XCUIApplication) throws {
        let inviteField = app.textFields["pairing.complete-invite"]
        XCTAssertTrue(
            inviteField.waitForExistence(timeout: 30),
            "production Companion 未进入真实 pairing 页面；禁止用 fixture 代替"
        )
        let confirmation = app.alerts["确认配对这台机器？"]
        XCTAssertTrue(
            confirmation.waitForExistence(timeout: 45),
            "真实 PairInvite 未完成本地检查或 Relay/production source 未 ready"
        )
        confirmation.buttons["核对无误，开始配对"].tap()
    }

    private func waitForPairingWaiting(in app: XCUIApplication) {
        let status = app.staticTexts["pairing.status"]
        XCTAssertTrue(status.waitForExistence(timeout: 10))
        let waiting = NSPredicate(format: "label CONTAINS %@", "等待被控机器本地确认")
        expectation(for: waiting, evaluatedWith: status)
        waitForExpectations(timeout: 45)
    }

    private func openOriginalConversation(in app: XCUIApplication) throws {
        try openConversation(titled: Self.conversationTitle, in: app)
    }

    private func openConversation(titled title: String, in app: XCUIApplication) throws {
        let machineList = app.collectionViews["machines.list"]
        XCTAssertTrue(machineList.waitForExistence(timeout: 90))
        let machine = machineList.cells.firstMatch
        XCTAssertTrue(machine.waitForExistence(timeout: 90), "配对后未出现真实机器行")
        let online = NSPredicate(format: "label CONTAINS %@", "在线")
        expectation(for: online, evaluatedWith: machine)
        waitForExpectations(timeout: Self.businessReadyUIWait)
        machine.tap()

        let sessionList = app.collectionViews["sessions.list"]
        XCTAssertTrue(sessionList.waitForExistence(timeout: 30))
        let conversation = app.staticTexts[title]
        XCTAssertTrue(
            conversation.waitForExistence(timeout: Self.businessReadyUIWait),
            "真实 catalog 未出现目标会话"
        )
        conversation.tap()

        let input = app.textViews["session.prompt.input"]
        XCTAssertTrue(input.waitForExistence(timeout: 45), "production 会话详情未打开")
    }

    private func exercisePromptAndApproval(in app: XCUIApplication) {
        let input = app.textViews["session.prompt.input"]
        let send = app.buttons["session.prompt.send"]
        let promptReady = NSPredicate(format: "enabled == true")
        expectation(for: promptReady, evaluatedWith: send)
        waitForExpectations(timeout: Self.businessReadyUIWait)
        input.tap()
        input.typeText(Self.promptSentinel)
        XCTAssertTrue(send.isEnabled)
        send.tap()

        XCTAssertTrue(
            app.staticTexts["synthetic Codex response"].waitForExistence(timeout: 60),
            "synthetic adapter 输出未经过真实 daemon/Relay 到达 UI"
        )
        XCTAssertTrue(
            app.staticTexts["synthetic codex approval"].waitForExistence(timeout: 60),
            "真实 canonical approval 未到达 UI"
        )
        let events = app.collectionViews["session.events"]
        events.swipeUp()
        let approve = app.buttons["session.approval.approve"]
        XCTAssertTrue(approve.waitForExistence(timeout: 30))
        approve.tap()

        let state = app.staticTexts["session.approval.state"]
        XCTAssertTrue(state.waitForExistence(timeout: 30))
        let applied = NSPredicate(format: "label CONTAINS %@", "已应用批准")
        expectation(for: applied, evaluatedWith: state)
        waitForExpectations(timeout: 60)
    }

    private func navigateBack(in app: XCUIApplication) {
        let back = app.navigationBars.buttons.element(boundBy: 0)
        XCTAssertTrue(back.waitForExistence(timeout: 30))
        back.tap()
    }

    private func signalLifecycleFence() throws {
        let documents = try XCTUnwrap(
            FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        )
        let destination = documents.appendingPathComponent(
            Self.lifecycleFenceName,
            isDirectory: false
        )
        try Data("business-observed\n".utf8).write(to: destination, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: UInt16(0o600))],
            ofItemAtPath: destination.path
        )
    }

    private func loadPrivateInvite() throws -> String {
        let environmentPath = ProcessInfo.processInfo.environment[Self.invitePathEnvironment]
        let testBundle = Bundle(for: Self.self)
        let resourceURL = testBundle.url(
            forResource: Self.inviteResourceName,
            withExtension: "secret"
        )
        if let environmentPath, let resourceURL, environmentPath != resourceURL.path {
            throw RelayCompanionUIHarnessError.conflictingPrivateInvitePath
        }

        let privateURL: URL
        let removesPrivateCopy: Bool
        if let environmentPath {
            privateURL = try validatedInjectedURL(environmentPath)
            removesPrivateCopy = false
        } else if let resourceURL {
            privateURL = try stagePrivateCopy(of: resourceURL)
            removesPrivateCopy = true
        } else {
            throw RelayCompanionUIHarnessError.missingPrivateInvitePath
        }
        defer {
            if removesPrivateCopy {
                try? FileManager.default.removeItem(at: privateURL)
            }
        }

        let values = try privateURL.resourceValues(forKeys: [
            .isRegularFileKey,
            .isSymbolicLinkKey,
            .fileSizeKey,
        ])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
            let size = values.fileSize, size > 0, size <= 65_536
        else {
            throw RelayCompanionUIHarnessError.unsafePrivateInvitePath
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: privateURL.path)
        guard
            let permissions = attributes[.posixPermissions] as? NSNumber,
            permissions.uint16Value & 0o077 == 0
        else {
            throw RelayCompanionUIHarnessError.unsafePrivateInvitePermissions
        }

        let rawInvite = try String(contentsOf: privateURL, encoding: .utf8)
        let invite = rawInvite.trimmingCharacters(in: .whitespacesAndNewlines)
        guard invite.hasPrefix("agentdeck-pair:v1:"), !invite.contains("\n"),
            !invite.contains("\r"), invite.utf8.count <= 65_536
        else {
            throw RelayCompanionUIHarnessError.invalidPrivateInvite
        }
        return invite
    }

    private func validatedInjectedURL(_ rawPath: String) throws -> URL {
        guard
            !rawPath.isEmpty,
            rawPath.hasPrefix("/"),
            !rawPath.contains("\n"),
            !rawPath.contains("\r")
        else {
            throw RelayCompanionUIHarnessError.missingPrivateInvitePath
        }
        let url = URL(fileURLWithPath: rawPath).standardizedFileURL
        guard normalizedTemporaryPath(url.path) == normalizedTemporaryPath(rawPath) else {
            throw RelayCompanionUIHarnessError.unsafePrivateInvitePath
        }
        return url
    }

    private func stagePrivateCopy(of resourceURL: URL) throws -> URL {
        let values = try resourceURL.resourceValues(forKeys: [
            .isRegularFileKey,
            .isSymbolicLinkKey,
            .fileSizeKey,
        ])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
            let size = values.fileSize, size > 0, size <= 65_536
        else {
            throw RelayCompanionUIHarnessError.unsafeBundledInvite
        }
        let data = try Data(contentsOf: resourceURL)
        let destination = FileManager.default.temporaryDirectory.appendingPathComponent(
            "relay-companion-invite-\(UUID().uuidString).secret"
        )
        let created = FileManager.default.createFile(
            atPath: destination.path,
            contents: nil,
            attributes: [.posixPermissions: NSNumber(value: UInt16(0o600))]
        )
        guard created else {
            throw RelayCompanionUIHarnessError.privateInviteCopyFailed
        }
        do {
            let handle = try FileHandle(forWritingTo: destination)
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            try FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: UInt16(0o600))],
                ofItemAtPath: destination.path
            )
            return destination
        } catch {
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }

    private func normalizedTemporaryPath(_ path: String) -> String {
        let privatePrefix = "/private/tmp/"
        guard path.hasPrefix(privatePrefix) else { return path }
        return "/tmp/" + String(path.dropFirst(privatePrefix.count))
    }
}

private enum RelayCompanionUIHarnessError: Error {
    case missingPrivateInvitePath
    case conflictingPrivateInvitePath
    case unsafePrivateInvitePath
    case unsafePrivateInvitePermissions
    case unsafeBundledInvite
    case privateInviteCopyFailed
    case invalidPrivateInvite
}
