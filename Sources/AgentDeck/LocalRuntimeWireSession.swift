import AgentDeckCore
import Foundation

/// App model 使用的本机 Runtime v4 wire 边界。它只在已经完成安全 UDS/Hello 的
/// `RuntimeEnvelopeClient` 上收窄 API，不拥有 daemon 生命周期，也没有 spawn/fallback。
actor LocalRuntimeWireSession {
  private let client: RuntimeEnvelopeClient
  private let beforeStreamRead: @Sendable () async -> Void
  private var firstFacadeFault: RuntimeEnvelopeClientFailure?
  private var streamReadActive = false

  /// Production composition 只能从 OS account installation 派生 canonical endpoint。
  init(installation: LocalClientInstallation) {
    client = RuntimeEnvelopeClient(installation: installation)
    beforeStreamRead = {}
  }

  static func forOSAccount() throws -> LocalRuntimeWireSession {
    LocalRuntimeWireSession(installation: try LocalClientInstallation.forOSAccount())
  }

  /// 显式 test/component seam。`beforeStreamRead` 只用于确定性证明 facade 的单 reader
  /// ownership；production constructor 不接受该 hook。
  init(
    client: RuntimeEnvelopeClient,
    beforeStreamRead: @escaping @Sendable () async -> Void = {}
  ) {
    self.client = client
    self.beforeStreamRead = beforeStreamRead
  }

  func start() async throws {
    try requireNoFacadeFault()
    do {
      try await client.start()
    } catch {
      throw exactFailure(error)
    }
  }

  /// 单 terminal request。Subscribe/Backfill 的多 reply 序列会由底层以
  /// `daemon.client.sequence_required` 精确拒绝。
  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    try requireNoFacadeFault()
    do {
      let item = try await client.request(request)
      return try await decodeReplyItem(item)
    } catch {
      throw exactFailure(error)
    }
  }

  /// 只接受拥有显式 SyncComplete/Failure terminal 的 Subscribe/Backfill。
  func beginSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> LocalRuntimeReplySequence {
    try requireNoFacadeFault()
    guard Self.isSynchronized(request) else {
      throw RuntimeEnvelopeClientFailure(
        code: "daemon.client.synchronized_request_required",
        message: "only Subscribe/Backfill use the synchronized reply API"
      )
    }
    do {
      let sequence = try await client.beginRequest(request)
      return LocalRuntimeReplySequence(sequence: sequence, session: self)
    } catch {
      throw exactFailure(error)
    }
  }

  /// facade 是底层 `nextStream` 的唯一 owner；不启动第二条后台 pump。actor reentrancy
  /// 期间若出现第二个 reader，整条 client connection 以底层既有 failure code fail-close。
  func nextStream() async throws -> LocalRuntimeStreamFrame {
    try requireNoFacadeFault()
    guard !streamReadActive else {
      let failure = RuntimeEnvelopeClientFailure(
        code: "daemon.client.stream_consumer_duplicate",
        message: "LocalRuntimeWireSession already has an active stream reader"
      )
      throw await latchFacadeFault(failure)
    }
    streamReadActive = true
    defer { streamReadActive = false }

    await beforeStreamRead()
    do {
      let frame = try await client.nextStream()
      let item = try await decodeStreamItem(frame.item)
      return LocalRuntimeStreamFrame(messageID: frame.messageID, item: item)
    } catch {
      throw exactFailure(error)
    }
  }

  func fault() async -> RuntimeEnvelopeClientFailure? {
    if let firstFacadeFault { return firstFacadeFault }
    return await client.fault()
  }

  /// 只关闭本 client fd/pumps；绝不发送 daemon shutdown RuntimeRequest。
  func close() async {
    await client.close()
  }

  fileprivate func decodeReplyItem(
    _ item: RuntimeEnvelopeReplyItem
  ) async throws -> RuntimeReplyV2 {
    try requireNoFacadeFault()
    switch item {
    case .reply(let reply):
      return reply
    case .transferComplete(let payload):
      do {
        return try LocalRuntimeV2TransferPayloadCodec.decodeReply(payload)
      } catch {
        throw await latchFacadeFault(Self.invalidTransferPayloadFailure())
      }
    }
  }

  fileprivate func currentFacadeFault() -> RuntimeEnvelopeClientFailure? {
    firstFacadeFault
  }

  private func decodeStreamItem(
    _ item: RuntimeEnvelopeStreamItem
  ) async throws -> RuntimeStreamItemV2 {
    switch item {
    case .message(let stream):
      return stream
    case .transferComplete(let payload):
      do {
        return try LocalRuntimeV2TransferPayloadCodec.decodeStream(payload)
      } catch {
        throw await latchFacadeFault(Self.invalidTransferPayloadFailure())
      }
    }
  }

  private func requireNoFacadeFault() throws {
    if let firstFacadeFault { throw firstFacadeFault }
  }

  private func exactFailure(_ error: Error) -> RuntimeEnvelopeClientFailure {
    if let firstFacadeFault { return firstFacadeFault }
    if let failure = error as? RuntimeEnvelopeClientFailure { return failure }
    return RuntimeEnvelopeClientFailure(
      code: "daemon.client.connection_closed",
      message: String(describing: error)
    )
  }

  private func latchFacadeFault(
    _ failure: RuntimeEnvelopeClientFailure
  ) async -> RuntimeEnvelopeClientFailure {
    if let firstFacadeFault { return firstFacadeFault }
    firstFacadeFault = failure
    await client.close()
    return failure
  }

  private static func isSynchronized(_ request: RuntimeRequestV2) -> Bool {
    switch request {
    case .subscribe, .backfill:
      true
    default:
      false
    }
  }

  private static func invalidTransferPayloadFailure() -> RuntimeEnvelopeClientFailure {
    RuntimeEnvelopeClientFailure(
      code: "daemon.client.transfer_invalid",
      message: "completed transfer is not one exact current Runtime v4 payload"
    )
  }
}

/// Synchronized request 的 typed sequence。底层 sequence 继续唯一拥有 terminal 状态：
/// Backfill/Snapshot 可以有多项，SyncComplete/Failure 后 `next()` 精确返回 nil。
actor LocalRuntimeReplySequence {
  nonisolated let messageID: RuntimeMessageID
  private let sequence: RuntimeEnvelopeReplySequence
  private let session: LocalRuntimeWireSession

  fileprivate init(
    sequence: RuntimeEnvelopeReplySequence,
    session: LocalRuntimeWireSession
  ) {
    messageID = sequence.messageID
    self.sequence = sequence
    self.session = session
  }

  func next() async throws -> RuntimeReplyV2? {
    if let failure = await session.currentFacadeFault() { throw failure }
    do {
      guard let item = try await sequence.next() else { return nil }
      return try await session.decodeReplyItem(item)
    } catch {
      if let failure = await session.currentFacadeFault() { throw failure }
      if let failure = error as? RuntimeEnvelopeClientFailure { throw failure }
      throw RuntimeEnvelopeClientFailure(
        code: "daemon.client.connection_closed",
        message: String(describing: error)
      )
    }
  }

  func cancel() async {
    await sequence.cancel()
  }
}

struct LocalRuntimeStreamFrame: Sendable {
  let messageID: RuntimeMessageID
  let item: RuntimeStreamItemV2
}

/// TransferPart 的 raw payload 不带 `reply`/`stream` discriminator；它是 daemon 在
/// current Runtime v4 DTO canonical encode 后的裸 payload。这里只接受当前 production
/// transfer egress 允许的大对象集合，并调用这些 DTO 自身的 strict current decoder。
private enum LocalRuntimeV2TransferPayloadCodec {
  private enum DecodeFailure: Error {
    case noExactPayload
  }

  static func decodeReply(_ payload: Data) throws -> RuntimeReplyV2 {
    var matches: [RuntimeReplyV2] = []
    let decoder = JSONDecoder()
    if let value = try? decoder.decode(RuntimeCatalogSnapshotV2.self, from: payload) {
      matches.append(.catalog(value))
    }
    if let value = try? decoder.decode(ConversationSnapshotV2.self, from: payload) {
      matches.append(.snapshot(value))
    }
    if let value = try? decoder.decode(RuntimeBackfillChunkV2.self, from: payload) {
      matches.append(.backfill(value))
    }
    guard matches.count == 1, let exact = matches.first else {
      throw DecodeFailure.noExactPayload
    }
    return exact
  }

  static func decodeStream(_ payload: Data) throws -> RuntimeStreamItemV2 {
    var matches: [RuntimeStreamItemV2] = []
    let decoder = JSONDecoder()
    if let value = try? decoder.decode(RuntimeEventV2.self, from: payload) {
      matches.append(.event(value))
    }
    if let value = try? decoder.decode(RuntimeCatalogDeltaV2.self, from: payload) {
      matches.append(.catalogDelta(value))
    }
    guard matches.count == 1, let exact = matches.first else {
      throw DecodeFailure.noExactPayload
    }
    return exact
  }
}
