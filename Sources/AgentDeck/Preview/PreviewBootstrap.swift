import AgentDeckSessionSource
import Foundation

/// preview 模式引导：显式注入 current Runtime v5 outer / `RuntimeEnvelopeV2` DTO fixture wire；
/// production composition 不引用它。
enum PreviewBootstrap {
  @MainActor
  static func makeSessionModel() -> SessionModel {
    let model = SessionModel(runtimeWire: PreviewRuntimeWireSession())
    model.environmentInfo = MockDaemonScript.environmentInfo
    return model
  }

  /// Preview 也显式走 registry 的 fixture scope；底层 concrete source 即使拥有
  /// local administration 实现，fixture handle 仍不会暴露这些 capability。
  @MainActor
  static func makeComposition() throws -> PreviewAppSessionSourceComposition {
    let binding = SessionModel.makeFixtureBinding(
      runtimeWire: PreviewRuntimeWireSession(),
      machineID: "preview-fixture"
    )
    binding.model.environmentInfo = MockDaemonScript.environmentInfo

    // Registry 的 production invariant 仍要求固定 local registration。Preview
    // 用一个从不 open 的独立 fixture wire 占住该槽，不能引用 production UDS。
    let localPlaceholder = LocalDaemonSessionSource(
      runtimeWire: PreviewRuntimeWireSession(),
      machineID: "preview-local-placeholder"
    )
    let registry = try SessionSourceRegistry(
      local: SessionSourceRegistration(
        scope: .local,
        source: localPlaceholder,
        capabilities: SessionSourceCapabilities(
          localPairingAdministration: localPlaceholder,
          localConversationAdministration: localPlaceholder
        ),
        lifecycle: localPlaceholder
      ),
      remoteFactory: { _ in throw PreviewCompositionError.remoteScopeUnavailable }
    )
    let fixtureRegistration = try SessionSourceRegistration(
      scope: .fixture(id: "preview"),
      source: binding.source,
      capabilities: SessionSourceCapabilities(),
      lifecycle: binding.source
    )
    let selectedMachineScope = SelectedMachineScopeGenerationOwner(registry: registry)
    return PreviewAppSessionSourceComposition(
      model: binding.model,
      registry: registry,
      selectedMachineScope: selectedMachineScope,
      fixtureRegistration: fixtureRegistration
    )
  }
}

enum PreviewCompositionError: Error, Sendable {
  case remoteScopeUnavailable
}

@MainActor
final class PreviewAppSessionSourceComposition: AppSessionSourceCompositionOwner {
  let model: SessionModel
  let registry: SessionSourceRegistry
  let selectedMachineScope: SelectedMachineScopeGenerationOwner
  private let fixtureRegistration: SessionSourceRegistration?
  private var didRegisterFixture = false
  private var isPrepared = false

  init(
    model: SessionModel,
    registry: SessionSourceRegistry,
    selectedMachineScope: SelectedMachineScopeGenerationOwner,
    fixtureRegistration: SessionSourceRegistration? = nil
  ) {
    self.model = model
    self.registry = registry
    self.selectedMachineScope = selectedMachineScope
    self.fixtureRegistration = fixtureRegistration
  }

  func prepare() async throws {
    guard !isPrepared else { return }
    guard let fixtureRegistration else {
      isPrepared = true
      return
    }
    if !didRegisterFixture {
      try await registry.registerFixture(fixtureRegistration)
      didRegisterFixture = true
    }
    _ = try await selectedMachineScope.select(.fixture(id: "preview"))
    isPrepared = true
  }

  func shutdown() async {
    model.teardown()
    await selectedMachineScope.shutdown()
    await registry.shutdown()
    await model.shutdown()
  }
}
