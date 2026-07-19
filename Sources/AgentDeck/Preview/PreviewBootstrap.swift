import Foundation

/// preview 模式引导：显式注入 Runtime v2 fixture wire；production composition 不引用它。
enum PreviewBootstrap {
  @MainActor
  static func makeSessionModel() -> SessionModel {
    let model = SessionModel(runtimeWire: PreviewRuntimeWireSession())
    model.environmentInfo = MockDaemonScript.environmentInfo
    return model
  }
}
