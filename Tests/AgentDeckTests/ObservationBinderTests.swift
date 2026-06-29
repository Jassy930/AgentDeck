import XCTest
import Observation
@testable import AgentDeck

@MainActor
final class ObservationBinderTests: XCTestCase {
    @Observable final class Counter { var value = 0 }

    func testOnChangeFiresOnEachMutation() async {
        let counter = Counter()
        let binder = ObservationBinder()
        var fires = 0
        binder.bind({ _ = counter.value }, onChange: { fires += 1 })

        counter.value = 1
        // 等待 MainActor 调度的 onChange 运行（可能需要多次 yield）
        var waited = 0
        while fires < 1 && waited < 20 {
            await Task.yield()
            waited += 1
        }

        counter.value = 2            // 第二次变化 —— 验证已 re-arm
        waited = 0
        while fires < 2 && waited < 20 {
            await Task.yield()
            waited += 1
        }

        XCTAssertGreaterThanOrEqual(fires, 2, "onChange 应在每次变化后触发（含 re-arm）")
        binder.invalidate()
    }

    func testInvalidateStopsObservation() async {
        let counter = Counter()
        let binder = ObservationBinder()
        var fires = 0
        binder.bind({ _ = counter.value }, onChange: { fires += 1 })
        binder.invalidate()
        counter.value = 99
        // 等待足够时间确认 onChange 不触发
        for _ in 0..<20 {
            await Task.yield()
        }
        XCTAssertEqual(fires, 0, "invalidate 后不应再触发")
    }
}
