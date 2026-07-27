import AVFoundation
import Foundation
import UIKit

/// 只读取完整 `agentdeck-pair:v1:<base64url>` 邀请；低熵短 PIN 永远不会进入配对状态机。
@MainActor
final class QRCodeScannerViewController: UIViewController {
    var onInvite: ((String) -> Void)?

    private let statusLabel = UILabel()
    private var captureRunner: QRCodeCaptureRunner?
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var deliveredInvite = false
    private var visibilityGate = QRScannerVisibilityGate()

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "扫描完整配对邀请"
        view.backgroundColor = DesignTokens.bg

        statusLabel.text = "将机器上的完整配对二维码放入取景框"
        statusLabel.textAlignment = .center
        statusLabel.numberOfLines = 0
        statusLabel.textColor = DesignTokens.text2
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(statusLabel)
        NSLayoutConstraint.activate([
            statusLabel.leadingAnchor.constraint(
                equalTo: view.leadingAnchor,
                constant: DesignTokens.sp4
            ),
            statusLabel.trailingAnchor.constraint(
                equalTo: view.trailingAnchor,
                constant: -DesignTokens.sp4
            ),
            statusLabel.bottomAnchor.constraint(
                equalTo: view.safeAreaLayoutGuide.bottomAnchor,
                constant: -DesignTokens.sp4
            ),
        ])

        let captureRunner = QRCodeCaptureRunner()
        self.captureRunner = captureRunner
        let layer = AVCaptureVideoPreviewLayer(session: captureRunner.captureSession)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.insertSublayer(layer, at: 0)
        previewLayer = layer

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(sceneDidActivate(_:)),
            name: UIScene.didActivateNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(sceneWillDeactivate(_:)),
            name: UIScene.willDeactivateNotification,
            object: nil
        )
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        deliveredInvite = false
        visibilityGate.viewWillAppear()
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard view.window?.windowScene?.activationState == .foregroundActive,
            let visibilityID = visibilityGate.sceneDidActivate()
        else { return }
        requestCameraAndStart(visibilityID: visibilityID)
    }

    override func viewWillDisappear(_ animated: Bool) {
        if let visibilityID = visibilityGate.viewWillDisappear() {
            stopCapture(visibilityID: visibilityID)
        }
        super.viewWillDisappear(animated)
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    @objc private func sceneDidActivate(_ notification: Notification) {
        guard !deliveredInvite, notificationBelongsToCurrentScene(notification),
            let visibilityID = visibilityGate.sceneDidActivate()
        else { return }
        requestCameraAndStart(visibilityID: visibilityID)
    }

    @objc private func sceneWillDeactivate(_ notification: Notification) {
        guard notificationBelongsToCurrentScene(notification),
            let visibilityID = visibilityGate.sceneWillDeactivate()
        else { return }
        stopCapture(visibilityID: visibilityID)
    }

    private func notificationBelongsToCurrentScene(_ notification: Notification) -> Bool {
        guard let notifiedScene = notification.object as? UIWindowScene,
            let currentScene = view.window?.windowScene
        else { return false }
        return notifiedScene === currentScene
    }

    private func requestCameraAndStart(visibilityID: UUID) {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            startCapture(visibilityID: visibilityID)
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                Task { @MainActor in
                    guard let self,
                        self.visibilityGate.allowsStart(visibilityID: visibilityID)
                    else { return }
                    if granted {
                        self.startCapture(visibilityID: visibilityID)
                    } else {
                        self.showUnavailable(
                            "相机权限未开启，请在系统设置中授权后重试",
                            visibilityID: visibilityID
                        )
                    }
                }
            }
        case .denied, .restricted:
            showUnavailable(
                "相机不可用；也可以返回后粘贴完整配对邀请",
                visibilityID: visibilityID
            )
        @unknown default:
            showUnavailable(
                "无法确认相机权限；请粘贴完整配对邀请",
                visibilityID: visibilityID
            )
        }
    }

    private func startCapture(visibilityID: UUID) {
        guard visibilityGate.allowsStart(visibilityID: visibilityID),
            let captureRunner
        else { return }
        captureRunner.start(
            visibilityID: visibilityID,
            onMetadata: { [weak self] callbackVisibilityID, values in
                self?.receiveMetadata(
                    visibilityID: callbackVisibilityID,
                    values: values
                )
            },
            completion: { [weak self] result in
                guard let self,
                    self.visibilityGate.allowsStart(visibilityID: visibilityID)
                else { return }
                switch result {
                case .success:
                    self.statusLabel.text = "将机器上的完整配对二维码放入取景框"
                case .failure:
                    self.showUnavailable(
                        "无法启动相机；请粘贴完整配对邀请",
                        visibilityID: visibilityID
                    )
                }
            }
        )
    }

    private func stopCapture(visibilityID: UUID) {
        captureRunner?.stop(visibilityID: visibilityID)
    }

    private func showUnavailable(_ message: String, visibilityID: UUID) {
        guard visibilityGate.allowsStart(visibilityID: visibilityID) else { return }
        stopCapture(visibilityID: visibilityID)
        statusLabel.text = message
    }

    private func receiveMetadata(visibilityID: UUID, values: [String]) {
        guard visibilityGate.allowsCallback(visibilityID: visibilityID),
            !deliveredInvite
        else { return }
        guard
            let value =
                values.compactMap(PairInviteInput.normalized).first
        else {
            statusLabel.text = "二维码不是完整 AgentDeck 配对邀请"
            return
        }
        guard visibilityGate.consume(visibilityID: visibilityID) else { return }
        deliveredInvite = true
        stopCapture(visibilityID: visibilityID)
        onInvite?(value)
    }
}

struct QRScannerVisibilityGate {
    private(set) var viewIsVisible = false
    private(set) var sceneIsActive = false
    private(set) var visibilityID: UUID?
    private var generationConsumed = false

    var isVisible: Bool { viewIsVisible }

    mutating func viewWillAppear() {
        viewIsVisible = true
        generationConsumed = false
    }

    @discardableResult
    mutating func viewWillDisappear() -> UUID? {
        viewIsVisible = false
        return invalidateCurrentGeneration()
    }

    mutating func sceneDidActivate() -> UUID? {
        sceneIsActive = true
        guard viewIsVisible, !generationConsumed, visibilityID == nil else { return nil }
        let visibilityID = UUID()
        self.visibilityID = visibilityID
        return visibilityID
    }

    @discardableResult
    mutating func sceneWillDeactivate() -> UUID? {
        sceneIsActive = false
        return invalidateCurrentGeneration()
    }

    mutating func consume(visibilityID: UUID) -> Bool {
        guard allowsCallback(visibilityID: visibilityID) else { return false }
        self.visibilityID = nil
        generationConsumed = true
        return true
    }

    func allowsStart(visibilityID: UUID) -> Bool {
        viewIsVisible && sceneIsActive && self.visibilityID == visibilityID
    }

    func allowsCallback(visibilityID: UUID) -> Bool {
        allowsStart(visibilityID: visibilityID)
    }

    private mutating func invalidateCurrentGeneration() -> UUID? {
        defer { visibilityID = nil }
        return visibilityID
    }
}

private final class QRCodeCaptureRunner: @unchecked Sendable {
    let captureSession = AVCaptureSession()

    private let queue = DispatchQueue(label: "dev.agentdeck.mobile.qr-capture")
    private let metadataQueue = DispatchQueue(label: "dev.agentdeck.mobile.qr-metadata")
    private var configurationResult: Result<Void, QRScannerFailure>?
    private var metadataOutput: AVCaptureMetadataOutput?
    private var metadataProxies: [UUID: QRCodeMetadataProxy] = [:]
    private var ownershipGate = QRScannerCaptureOwnershipGate()

    func start(
        visibilityID: UUID,
        onMetadata: @escaping @MainActor @Sendable (UUID, [String]) -> Void,
        completion: @escaping @MainActor @Sendable (Result<Void, QRScannerFailure>) -> Void
    ) {
        queue.async { [self] in
            let result = configureIfNeeded()
            if case .success = result {
                ownershipGate.activate(visibilityID: visibilityID)
                let proxy = QRCodeMetadataProxy(
                    visibilityID: visibilityID,
                    onMetadata: onMetadata
                )
                metadataProxies[visibilityID] = proxy
                metadataOutput?.setMetadataObjectsDelegate(proxy, queue: metadataQueue)
            }
            if case .success = result, !captureSession.isRunning {
                captureSession.startRunning()
            }
            Task { @MainActor in
                completion(result)
            }
        }
    }

    func stop(visibilityID: UUID) {
        queue.async { [self] in
            guard ownershipGate.deactivate(visibilityID: visibilityID) else { return }
            metadataOutput?.setMetadataObjectsDelegate(nil, queue: nil)
            if captureSession.isRunning {
                captureSession.stopRunning()
            }
            // 已排进 metadataQueue 的旧 callback 必须继续由原 proxy 携带原 UUID。
            // 先经过 metadataQueue barrier，再回 owner queue 释放该 generation。
            metadataQueue.async { [self] in
                queue.async { [self] in
                    metadataProxies[visibilityID] = nil
                }
            }
        }
    }

    private func configureIfNeeded() -> Result<Void, QRScannerFailure> {
        if let configurationResult { return configurationResult }

        let result: Result<Void, QRScannerFailure>
        do {
            try configureCaptureSession()
            result = .success(())
        } catch let failure as QRScannerFailure {
            result = .failure(failure)
        } catch {
            result = .failure(.inputUnavailable)
        }
        configurationResult = result
        return result
    }

    private func configureCaptureSession() throws {
        guard let camera = AVCaptureDevice.default(for: .video) else {
            throw QRScannerFailure.cameraUnavailable
        }
        let input = try AVCaptureDeviceInput(device: camera)
        let output = AVCaptureMetadataOutput()
        guard captureSession.canAddInput(input), captureSession.canAddOutput(output) else {
            throw QRScannerFailure.unsupportedConfiguration
        }

        captureSession.beginConfiguration()
        defer { captureSession.commitConfiguration() }
        captureSession.addInput(input)
        captureSession.addOutput(output)
        guard output.availableMetadataObjectTypes.contains(.qr) else {
            throw QRScannerFailure.unsupportedConfiguration
        }
        output.metadataObjectTypes = [.qr]
        metadataOutput = output
    }
}

struct QRScannerCaptureOwnershipGate {
    private(set) var activeVisibilityID: UUID?

    mutating func activate(visibilityID: UUID) {
        activeVisibilityID = visibilityID
    }

    func owns(visibilityID: UUID) -> Bool {
        activeVisibilityID == visibilityID
    }

    mutating func deactivate(visibilityID: UUID) -> Bool {
        guard owns(visibilityID: visibilityID) else { return false }
        activeVisibilityID = nil
        return true
    }
}

private final class QRCodeMetadataProxy: NSObject, AVCaptureMetadataOutputObjectsDelegate,
    @unchecked Sendable
{
    private let visibilityID: UUID
    private let onMetadata: @MainActor @Sendable (UUID, [String]) -> Void

    init(
        visibilityID: UUID,
        onMetadata: @escaping @MainActor @Sendable (UUID, [String]) -> Void
    ) {
        self.visibilityID = visibilityID
        self.onMetadata = onMetadata
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        _ = output
        _ = connection
        let values =
            metadataObjects.compactMap {
                ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue
            }
        Task { @MainActor [onMetadata, values, visibilityID] in
            onMetadata(visibilityID, values)
        }
    }
}

private enum QRScannerFailure: Error, Sendable {
    case cameraUnavailable
    case inputUnavailable
    case unsupportedConfiguration
}
