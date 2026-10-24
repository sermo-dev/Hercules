import AVFoundation
import SwiftUI

struct WalletImportView: View {
    @ObservedObject var viewModel: NodeViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var xpubText = ""
    @State private var showScanner = false
    @State private var validationError: String?

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.bg.ignoresSafeArea(.all)

                VStack(spacing: 24) {
                    VStack(spacing: 8) {
                        Image(systemName: "key.fill")
                            .font(.system(size: 36, weight: .light))
                            .foregroundStyle(Theme.accent)

                        Text("Import Watch-Only Wallet")
                            .font(.system(size: 18, weight: .semibold))
                            .foregroundStyle(Theme.textPrimary)

                        Text("Paste or scan your account-level\nextended public key (xpub/zpub).")
                            .font(.system(size: 13))
                            .foregroundStyle(Theme.textSecondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding(.top, 24)

                    // Text field
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("xpub... or zpub...", text: $xpubText, axis: .vertical)
                            .font(.system(size: 13, design: .monospaced))
                            .foregroundStyle(Theme.textPrimary)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .lineLimit(3...6)
                            .padding(12)
                            .background(Theme.card)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(Theme.cardBorder, lineWidth: 1)
                            )

                        if let err = validationError {
                            Text(err)
                                .font(.system(size: 12))
                                .foregroundStyle(Theme.error)
                        }
                    }
                    .padding(.horizontal, 20)

                    // Scan QR button
                    Button(action: { showScanner = true }) {
                        HStack(spacing: 8) {
                            Image(systemName: "qrcode.viewfinder")
                                .font(.system(size: 16))
                            Text("Scan QR Code")
                                .font(.system(size: 14, weight: .medium))
                        }
                        .foregroundStyle(Theme.accent)
                    }

                    Spacer()

                    // Import button
                    Button(action: doImport) {
                        Text("Import")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(isValid ? Theme.accent : Theme.accent.opacity(0.3))
                            .clipShape(RoundedRectangle(cornerRadius: 14))
                    }
                    .disabled(!isValid)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 20)
                }
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .foregroundStyle(Theme.textSecondary)
                }
            }
            .sheet(isPresented: $showScanner) {
                QRScannerView { code in
                    xpubText = code
                    showScanner = false
                }
            }
        }
    }

    private var isValid: Bool {
        let trimmed = xpubText.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.hasPrefix("xpub") || trimmed.hasPrefix("zpub") || trimmed.hasPrefix("ypub")
    }

    private func doImport() {
        let trimmed = xpubText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isValid else {
            validationError = "Enter a valid xpub, zpub, or ypub"
            return
        }
        validationError = nil
        viewModel.importWallet(xpub: trimmed)
        dismiss()
    }
}

// MARK: - QR Scanner

struct QRScannerView: UIViewControllerRepresentable {
    var onCode: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onCode: onCode)
    }

    func makeUIViewController(context: Context) -> ScannerViewController {
        let vc = ScannerViewController()
        vc.delegate = context.coordinator
        return vc
    }

    func updateUIViewController(_ vc: ScannerViewController, context: Context) {}

    class Coordinator: NSObject, ScannerDelegate {
        let onCode: (String) -> Void
        init(onCode: @escaping (String) -> Void) { self.onCode = onCode }
        func didFind(code: String) { onCode(code) }
    }
}

protocol ScannerDelegate: AnyObject {
    func didFind(code: String)
}

class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    weak var delegate: ScannerDelegate?
    private let session = AVCaptureSession()
    private var found = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device) else {
            return
        }

        if session.canAddInput(input) { session.addInput(input) }

        let output = AVCaptureMetadataOutput()
        if session.canAddOutput(output) {
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
        }

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.frame = view.layer.bounds
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview)

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.session.startRunning()
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        session.stopRunning()
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput results: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !found,
              let obj = results.first as? AVMetadataMachineReadableCodeObject,
              let code = obj.stringValue else { return }
        found = true
        delegate?.didFind(code: code)
    }
}
