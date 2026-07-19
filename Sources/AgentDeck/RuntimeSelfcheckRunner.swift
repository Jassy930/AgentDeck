import AgentDeckCore
import Foundation

struct RuntimeSelfcheckExecution: Equatable, Sendable {
  let exitCode: Int32
  let stdout: Data
  let stderr: Data
}

/// 对 canonical shared-daemon Runtime v2 入口执行最小健康检查。
///
/// `start()` 已完成 installation、UDS 与 Hello；这里随后只请求一次
/// `DescribeAgents`，并且无论成功或失败都只关闭当前 client connection。
struct RuntimeSelfcheckRunner: Sendable {
  typealias WireFactory = @Sendable () throws -> any AppRuntimeWireSession

  private struct SuccessPayload: Encodable {
    let agents: [String]
    let ok: Bool
    let protocolVersion: UInt16
    let reply: String
  }

  private struct FailurePayload: Encodable {
    private enum CodingKeys: String, CodingKey {
      case code
      case diagnosticRef
      case message
      case ok
      case reply
    }

    let code: String
    let diagnosticRef: String?
    let message: String

    func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(code, forKey: .code)
      try container.encode(diagnosticRef, forKey: .diagnosticRef)
      try container.encode(message, forKey: .message)
      try container.encode(false, forKey: .ok)
      try container.encode("selfcheck", forKey: .reply)
    }
  }

  private let wireFactory: WireFactory

  init(
    wireFactory: @escaping WireFactory = {
      OSAccountRuntimeWireSession()
    }
  ) {
    self.wireFactory = wireFactory
  }

  func run() async -> RuntimeSelfcheckExecution {
    let wire: any AppRuntimeWireSession
    do {
      wire = try wireFactory()
    } catch {
      return Self.failureExecution(for: error)
    }

    let execution: RuntimeSelfcheckExecution
    do {
      try await wire.start()
      execution = Self.execution(for: try await wire.request(.describeAgents))
    } catch {
      execution = Self.failureExecution(for: error)
    }
    await wire.close()
    return execution
  }

  private static func execution(for reply: RuntimeReplyV2) -> RuntimeSelfcheckExecution {
    switch reply {
    case .agents(let descriptions):
      let payload = SuccessPayload(
        agents: descriptions.agents.map(\.agentKind.rawValue).sorted(),
        ok: true,
        protocolVersion: runtimeProtocolVersionCurrent,
        reply: "selfcheck"
      )
      guard let stdout = encodedLine(payload) else {
        return failureExecution(
          code: "daemon.client.selfcheck_failed",
          message: "failed to encode selfcheck result"
        )
      }
      return RuntimeSelfcheckExecution(
        exitCode: 0,
        stdout: stdout,
        stderr: Data()
      )
    case .failure(let failure):
      return failureExecution(
        code: failure.code,
        message: failure.message,
        diagnosticRef: failure.diagnosticRef
      )
    default:
      return failureExecution(
        code: "daemon.client.selfcheck_reply_invalid",
        message: "DescribeAgents returned an unexpected Runtime reply"
      )
    }
  }

  private static func failureExecution(for error: any Error) -> RuntimeSelfcheckExecution {
    if let failure = error as? RuntimeEnvelopeClientFailure {
      return failureExecution(code: failure.code, message: failure.message)
    }
    if let failure = error as? LocalClientInstallationError {
      return failureExecution(code: failure.code, message: failure.description)
    }
    if let failure = error as? UnixSocketDaemonTransportError {
      return failureExecution(code: failure.code, message: failure.description)
    }
    return failureExecution(
      code: "daemon.client.selfcheck_failed",
      message: String(describing: error)
    )
  }

  private static func failureExecution(
    code: String,
    message: String,
    diagnosticRef: String? = nil
  ) -> RuntimeSelfcheckExecution {
    let payload = FailurePayload(
      code: code,
      diagnosticRef: diagnosticRef,
      message: message
    )
    return RuntimeSelfcheckExecution(
      exitCode: 1,
      stdout: Data(),
      stderr: encodedLine(payload) ?? encodingFailureLine()
    )
  }

  private static func encodedLine<T: Encodable>(_ payload: T) -> Data? {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    do {
      var data = try encoder.encode(payload)
      data.append(0x0A)
      return data
    } catch {
      return nil
    }
  }

  private static func encodingFailureLine() -> Data {
    var data = Data(
      #"{"code":"daemon.client.selfcheck_failed","diagnosticRef":null,"message":"failed to encode selfcheck result","ok":false,"reply":"selfcheck"}"#
        .utf8
    )
    data.append(0x0A)
    return data
  }
}
