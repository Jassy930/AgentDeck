import AgentDeckCore
import AgentDeckSessionSource
import Foundation

extension LocalDaemonSessionSource {
  static func publicFailure(_ error: (any Error)?) -> SessionSourceFailure {
    if let failure = error as? SessionSourceFailure { return failure }
    if let failure = error as? RuntimeEnvelopeClientFailure {
      let code: SessionSourceFailureCode
      switch failure.code {
      case "daemon.runtime.protocol_mismatch":
        code = .incompatible
      case "daemon.authorization.revoked":
        code = .revoked
      case "daemon.client.already_started",
        "daemon.client.not_started",
        "daemon.client.sequence_required",
        "daemon.client.synchronized_request_required",
        "daemon.client.stream_consumer_duplicate",
        "daemon.client.reply_consumer_duplicate",
        "daemon.client.frame_invalid",
        "daemon.client.hello_invalid",
        "daemon.client.hello_order_invalid",
        "daemon.client.server_request_forbidden",
        "daemon.client.reply_uncorrelated",
        "daemon.client.reply_backpressure",
        "daemon.client.reply_sequence_backpressure",
        "daemon.client.stream_backpressure",
        "daemon.client.transfer_incomplete",
        "daemon.client.transfer_invalid",
        "daemon.client.transfer_binding_mismatch",
        "daemon.client.transfer_backpressure",
        "daemon.client.message_id_duplicate",
        "daemon.client.message_id_invalid",
        "daemon.client.encode_failed":
        code = .securityError
      default:
        code = .transportUnavailable
      }
      return SessionSourceFailure(
        code: code,
        message: failure.message
      )
    }
    if error is LocalClientInstallationError {
      return SessionSourceFailure(code: .storageUnavailable)
    }
    if let coordinatorError = error as? AppRuntimeCoordinatorError {
      switch coordinatorError {
      case .closed:
        return SessionSourceFailure(code: .transportUnavailable)
      case .daemonFailure(let code, let message, let diagnosticRef):
        let publicCode: SessionSourceFailureCode
        switch code {
        case "daemon.authorization.revoked":
          publicCode = .revoked
        case "daemon.runtime.protocol_mismatch":
          publicCode = .incompatible
        case "daemon.runtime.store_unavailable",
          "daemon.runtime.store_full",
          "daemon.runtime.disk_low":
          publicCode = .storageUnavailable
        case "daemon.runtime.not_ready",
          "daemon.runtime.recovering",
          "daemon.runtime.store_busy",
          "daemon.runtime.actor_unavailable":
          publicCode = .transportUnavailable
        default:
          publicCode = .commandRejected
        }
        return SessionSourceFailure(
          code: publicCode,
          message: message,
          diagnosticReference: diagnosticRef
        )
      case .configurationConflict, .operationInProgress:
        return SessionSourceFailure(code: .commandRejected)
      case .notStarted, .alreadyStarted, .unexpectedReply,
        .receiptConversationMismatch, .receiptApprovalMismatch,
        .receiptPairingMismatch, .receiptConfigurationRevisionMismatch,
        .missingSubscriptionReceipt, .unexpectedUnsubscribeReceipt,
        .subscriptionGenerationMismatch, .synchronizationTargetMismatch,
        .missingSynchronizationTerminal, .replyAfterSynchronizationTerminal,
        .synchronizationReplyLimitExceeded, .catalogPageLimitExceeded,
        .catalogPageCursorCycle, .catalogPageCursorMismatch:
        return SessionSourceFailure(code: .securityError)
      }
    }
    if case nil = error { return SessionSourceFailure(code: .transportUnavailable) }
    return SessionSourceFailure(code: .securityError)
  }

  func connectionState(for error: any Error) -> SessionConnectionState {
    connectionState(for: Self.publicFailure(error))
  }

  func connectionState(
    for failure: SessionSourceFailure
  ) -> SessionConnectionState {
    switch failure.code {
    case .revoked: return .revoked
    case .incompatible: return .incompatible
    case .securityError: return .securityError
    case .machineOffline: return .machineOffline
    default: return .reconnecting
    }
  }

  static func failure(
    for reason: LocalConversationConnectionInvalidationReason
  ) -> SessionSourceFailure {
    switch reason {
    case .coordinatorClosed, .transportOrProtocolFault:
      return SessionSourceFailure(code: .transportUnavailable)
    case .failure(let failure):
      return failure
    }
  }

  static func isRetryable(_ failure: SessionSourceFailure) -> Bool {
    switch failure.code {
    case .transportUnavailable, .machineOffline, .storageUnavailable, .unknown:
      return true
    case .revoked, .incompatible, .securityError, .invalidPairInvite,
      .pairInviteExpired, .commandRejected:
      return false
    }
  }

  static func requiresConnectionInvalidation(
    _ failure: SessionSourceFailure
  ) -> Bool {
    switch failure.code {
    case .transportUnavailable, .revoked, .incompatible, .securityError:
      return true
    case .machineOffline, .invalidPairInvite, .pairInviteExpired,
      .commandRejected, .storageUnavailable, .unknown:
      return false
    }
  }

  func unsupportedLocalFacade(_ message: String) -> SessionSourceFailure {
    SessionSourceFailure(code: .commandRejected, message: message)
  }
}
