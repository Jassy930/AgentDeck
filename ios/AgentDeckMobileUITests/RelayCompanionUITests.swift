import Foundation
import XCTest

/// R4 fixed-topology 的首个真实 UI 契约。
///
/// invite 只通过 mode 0600 临时文件交给 UI test process；测试再复用 production
/// `--pair-invite` 入口启动 App。没有显式 harness 输入时必须 RED，不能退回 fixture。
final class RelayCompanionUITests: XCTestCase {
    private static let invitePathEnvironment = "AGENTDECK_RELAY_E2E_INVITE_PATH"

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    func testPairingReachesLocalConfirmation() throws {
        let invite = try loadPrivateInvite()
        let app = XCUIApplication()
        app.launchArguments = ["--pair-invite", invite]
        app.launch()

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

        let status = app.staticTexts["pairing.status"]
        XCTAssertTrue(status.waitForExistence(timeout: 10))
        let waiting = NSPredicate(format: "label CONTAINS %@", "等待被控机器本地确认")
        expectation(for: waiting, evaluatedWith: status)
        waitForExpectations(timeout: 45)
    }

    private func loadPrivateInvite() throws -> String {
        guard
            let rawPath = ProcessInfo.processInfo.environment[Self.invitePathEnvironment],
            rawPath.hasPrefix("/"),
            !rawPath.contains("\n"),
            !rawPath.contains("\r")
        else {
            throw RelayCompanionUIHarnessError.missingPrivateInvitePath
        }

        let url = URL(fileURLWithPath: rawPath).standardizedFileURL
        guard url.path == rawPath else {
            throw RelayCompanionUIHarnessError.unsafePrivateInvitePath
        }
        let values = try url.resourceValues(forKeys: [
            .isRegularFileKey,
            .isSymbolicLinkKey,
            .fileSizeKey,
        ])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
            let size = values.fileSize, size > 0, size <= 65_536
        else {
            throw RelayCompanionUIHarnessError.unsafePrivateInvitePath
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard
            let permissions = attributes[.posixPermissions] as? NSNumber,
            permissions.uint16Value & 0o077 == 0
        else {
            throw RelayCompanionUIHarnessError.unsafePrivateInvitePermissions
        }

        let rawInvite = try String(contentsOf: url, encoding: .utf8)
        let invite = rawInvite.trimmingCharacters(in: .whitespacesAndNewlines)
        guard invite.hasPrefix("agentdeck-pair:v1:"), !invite.contains("\n"),
            !invite.contains("\r"), invite.utf8.count <= 65_536
        else {
            throw RelayCompanionUIHarnessError.invalidPrivateInvite
        }
        return invite
    }
}

private enum RelayCompanionUIHarnessError: Error {
    case missingPrivateInvitePath
    case unsafePrivateInvitePath
    case unsafePrivateInvitePermissions
    case invalidPrivateInvite
}
