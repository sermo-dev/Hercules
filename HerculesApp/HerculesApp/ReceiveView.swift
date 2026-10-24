import CoreImage.CIFilterBuiltins
import SwiftUI

struct ReceiveView: View {
    let addressInfo: WalletAddressInfo
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.bg.ignoresSafeArea(.all)

                VStack(spacing: 24) {
                    Text("Receive Bitcoin")
                        .font(.system(size: 20, weight: .semibold))
                        .foregroundStyle(Theme.textPrimary)
                        .padding(.top, 16)

                    // QR Code
                    let uri = "bitcoin:\(addressInfo.address)"
                    if let qrImage = generateQR(from: uri) {
                        Image(uiImage: qrImage)
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                            .frame(width: 220, height: 220)
                            .padding(16)
                            .background(Color.white)
                            .clipShape(RoundedRectangle(cornerRadius: 16))
                    }

                    // Address
                    VStack(spacing: 8) {
                        Text(addressInfo.address)
                            .font(.system(size: 13, weight: .medium, design: .monospaced))
                            .foregroundStyle(Theme.textPrimary)
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)
                            .padding(.horizontal, 20)

                        HStack(spacing: 4) {
                            Image(systemName: "arrow.triangle.branch")
                                .font(.system(size: 10))
                            Text("m/84'/0'/0'/0/\(addressInfo.derivationIndex)")
                                .font(.system(size: 11, design: .monospaced))
                        }
                        .foregroundStyle(Theme.textTertiary)
                    }

                    // Copy button
                    Button(action: copyAddress) {
                        HStack(spacing: 8) {
                            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                                .font(.system(size: 14))
                            Text(copied ? "Copied" : "Copy Address")
                                .font(.system(size: 14, weight: .semibold))
                        }
                        .foregroundStyle(.white)
                        .padding(.horizontal, 24)
                        .padding(.vertical, 12)
                        .background(copied ? Theme.success : Theme.accent)
                        .clipShape(Capsule())
                    }

                    Spacer()
                }
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                        .foregroundStyle(Theme.accent)
                }
            }
        }
    }

    private func copyAddress() {
        UIPasteboard.general.string = addressInfo.address
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            copied = false
        }
    }

    private func generateQR(from string: String) -> UIImage? {
        let context = CIContext()
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"

        guard let output = filter.outputImage else { return nil }
        let scale = 300.0 / output.extent.width
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}
