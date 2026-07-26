/// P5.4 supervisor 交给重连策略的 typed 原因。策略本身不启动连接，也不跨
/// generation 自动重连。
public enum RelayReconnectReason: Equatable, Sendable {
  case transportFailure
  case serverRestarting(drainDeadlineMilliseconds: UInt64)
}

public enum RelayReconnectPolicyError: Error, Equatable, Sendable {
  case invalidJitterUnitInterval
}

/// Relay WSS 的纯重连延迟策略。
///
/// attempt 0 的指数退避基值固定为 250ms；之后每次翻倍，基值与 jitter 后的
/// 普通重连 delay 都硬上限为 30s。调用方注入 `[0, 1]` unit interval：0 映射
/// 到 -20%，0.5 映射到无 jitter，1 映射到 +20%。
public struct RelayReconnectPolicy: Equatable, Sendable {
  public static let initialDelayMilliseconds: UInt64 = 250
  public static let multiplier: UInt64 = 2
  public static let maximumDelayMilliseconds: UInt64 = 30_000
  public static let jitterFraction = 0.20

  public init() {}

  public func baseDelayMilliseconds(forAttempt attempt: UInt32) -> UInt64 {
    var delay = Self.initialDelayMilliseconds
    var remainingAttempts = attempt

    while remainingAttempts > 0, delay < Self.maximumDelayMilliseconds {
      let multiplied = delay.multipliedReportingOverflow(by: Self.multiplier)
      if multiplied.overflow {
        return Self.maximumDelayMilliseconds
      }
      delay = min(multiplied.partialValue, Self.maximumDelayMilliseconds)
      remainingAttempts -= 1
    }
    return delay
  }

  /// 返回 supervisor 在下一次 `connect()` 前应等待的毫秒数。
  ///
  /// `serverRestarting` 先等待 Relay drain deadline，再追加同一轮 jittered backoff，
  /// 避免全部客户端在 absolute deadline 同时重连。结果可超过普通 30s cap；所有
  /// 整数运算均 checked 或饱和。
  public func delayMilliseconds(
    forAttempt attempt: UInt32,
    reason: RelayReconnectReason,
    nowMilliseconds: UInt64,
    jitterUnitInterval: Double
  ) throws -> UInt64 {
    guard jitterUnitInterval.isFinite,
      (0.0...1.0).contains(jitterUnitInterval)
    else {
      throw RelayReconnectPolicyError.invalidJitterUnitInterval
    }

    let base = baseDelayMilliseconds(forAttempt: attempt)
    let centeredUnit = jitterUnitInterval * 2.0 - 1.0
    let jitter = Double(base) * Self.jitterFraction * centeredUnit
    let rounded = (Double(base) + jitter).rounded(.toNearestOrAwayFromZero)
    let bounded = min(
      Double(Self.maximumDelayMilliseconds),
      max(0.0, rounded)
    )
    let backoffDelay = UInt64(bounded)

    switch reason {
    case .transportFailure:
      return backoffDelay
    case .serverRestarting(let drainDeadlineMilliseconds):
      let remainingDrain: UInt64
      if drainDeadlineMilliseconds > nowMilliseconds {
        let difference = drainDeadlineMilliseconds.subtractingReportingOverflow(
          nowMilliseconds
        )
        remainingDrain = difference.overflow ? UInt64.max : difference.partialValue
      } else {
        remainingDrain = 0
      }
      let (scheduled, overflow) = remainingDrain.addingReportingOverflow(backoffDelay)
      return overflow ? UInt64.max : scheduled
    }
  }
}
