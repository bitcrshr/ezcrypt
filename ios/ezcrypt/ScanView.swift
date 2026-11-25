import SwiftUI

#if os(iOS)
  import AVFoundation
  import VisionKit

  /// Scans the QR code `ezcrypt` shows in a terminal. Without a camera (the
  /// Simulator, or no permission) the link can be pasted instead.
  struct ScanView: View {
    @Environment(LinkRouter.self) private var router
    @State private var available: Bool?
    var body: some View {
      Group {
        switch available {
        case nil:
          ProgressView()
        case true?:
          // Paused while an unreadable code's alert shows, then scans again.
          QRScanner(paused: router.error != nil) { router.open(pasted: $0) }
            .ignoresSafeArea(edges: .bottom)
            .overlay(alignment: .bottom) {
              Text("Point the camera at the QR code in the terminal.")
                .font(.subheadline).padding(.horizontal, 16).padding(.vertical, 10)
                .glassEffect().padding(24)
            }
        case false?:
          ContentUnavailableView {
            Label("Camera Unavailable", systemImage: "qrcode.viewfinder")
          } description: {
            Text(
              "Scanning needs camera access on an iPhone or iPad. Copy the ezcrypt:// link from the terminal and paste it here, or allow camera access in Settings."
            )
          } actions: {
            Button("Paste link", systemImage: "document.on.clipboard") {
              router.open(pasted: UIPasteboard.general.string)
            }
            .buttonStyle(.glassProminent).accessibilityIdentifier("paste-link")
          }
        }
      }
      .accessibilityIdentifier("scan-view")
      .navigationTitle("Scan").inlineNavigationTitle()
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button("Cancel") { router.close() }
        }
      }
      .task {
        if AVCaptureDevice.authorizationStatus(for: .video) == .notDetermined {
          _ = await AVCaptureDevice.requestAccess(for: .video)
        }
        available = DataScannerViewController.isSupported && DataScannerViewController.isAvailable
      }
    }
  }

  /// QR codes only; reports the first `ezcrypt://` payload once, then stops.
  private struct QRScanner: UIViewControllerRepresentable {
    let paused: Bool
    let found: (String) -> Void
    func makeCoordinator() -> Coordinator { Coordinator(found: found) }
    func makeUIViewController(context: Context) -> DataScannerViewController {
      let scanner = DataScannerViewController(
        recognizedDataTypes: [.barcode(symbologies: [.qr])], qualityLevel: .balanced,
        recognizesMultipleItems: false, isHighFrameRateTrackingEnabled: false,
        isHighlightingEnabled: true)
      scanner.delegate = context.coordinator
      return scanner
    }
    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {
      context.coordinator.found = found
      if paused {
        scanner.stopScanning()
        context.coordinator.done = false
      } else if !scanner.isScanning && !context.coordinator.done {
        try? scanner.startScanning()
      }
    }
    static func dismantleUIViewController(
      _ scanner: DataScannerViewController, coordinator: Coordinator
    ) {
      scanner.stopScanning()
    }
    @MainActor final class Coordinator: NSObject, DataScannerViewControllerDelegate {
      var found: (String) -> Void
      var done = false
      init(found: @escaping (String) -> Void) { self.found = found }
      func dataScanner(
        _ scanner: DataScannerViewController, didAdd added: [RecognizedItem],
        allItems: [RecognizedItem]
      ) {
        guard !done else { return }
        for item in added {
          guard case .barcode(let barcode) = item, let value = barcode.payloadStringValue,
            value.lowercased().hasPrefix("ezcrypt://")
          else { continue }
          done = true
          scanner.stopScanning()
          found(value)
          return
        }
      }
    }
  }
#else
  /// The Mac has no scanner: paste the link the terminal prints under its QR code.
  struct ScanView: View {
    @Environment(LinkRouter.self) private var router
    @State private var text = ""
    var body: some View {
      Form {
        Section {
          TextField("Link", text: $text, prompt: Text(verbatim: "ezcrypt://link?…"))
            .font(.body.monospaced()).autocorrectionDisabled()
            .onSubmit { router.open(pasted: text) }
            .accessibilityIdentifier("link-url")
        } footer: {
          Text("Copy the ezcrypt:// link printed under the QR code in the terminal.")
        }
      }
      .navigationTitle("Open Link")
      .actionBar {
        PrimaryButton(title: "Open", symbol: "link") { router.open(pasted: text) }
          .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
      }
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button("Cancel") { router.close() }
        }
      }
    }
  }
#endif
