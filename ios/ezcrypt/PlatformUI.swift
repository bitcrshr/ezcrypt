import SwiftUI
import UniformTypeIdentifiers

#if os(macOS)
  import AppKit
#endif

enum PlatformUI {
  static var authenticationSymbol: String {
    #if os(macOS)
      "touchid"
    #else
      "faceid"
    #endif
  }
  static var background: Color {
    #if os(macOS)
      Color(nsColor: .windowBackgroundColor)
    #else
      Color(.systemBackground)
    #endif
  }
  static func copy(_ value: String) {
    #if os(macOS)
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(value, forType: .string)
    #else
      UIPasteboard.general.string = value
    #endif
  }
}

extension View {
  @ViewBuilder func inlineNavigationTitle() -> some View {
    #if os(macOS)
      self
    #else
      navigationBarTitleDisplayMode(.inline)
    #endif
  }
  @ViewBuilder func verbatimInput() -> some View {
    #if os(macOS)
      self
    #else
      textInputAutocapitalization(.never)
    #endif
  }
  @ViewBuilder func serialKeyboard() -> some View {
    #if os(macOS)
      self
    #else
      keyboardType(.numberPad)
    #endif
  }
  @ViewBuilder func editorSize() -> some View {
    #if os(macOS)
      self.formStyle(.grouped).frame(
        minWidth: 560, idealWidth: 620, minHeight: 540, idealHeight: 680)
    #else
      self
    #endif
  }
}

#if os(macOS)
  /// Uses a system Save panel and keeps file access within the user's selection.
  struct SaveFileButton: View {
    let file: URL
    let title: String
    @State private var document: ExportDocument?
    @State private var saving = false
    @State private var error: String?
    var body: some View {
      Button(title, systemImage: "square.and.arrow.down") {
        do {
          document = ExportDocument(data: try Data(contentsOf: file))
          saving = true
        } catch { self.error = error.localizedDescription }
      }
      .fileExporter(
        isPresented: $saving, document: document, contentType: .data,
        defaultFilename: file.lastPathComponent
      ) { result in
        if case .failure(let failure) = result { error = failure.localizedDescription }
        document = nil
      }
      .alert(
        "Couldn’t save file",
        isPresented: Binding(
          get: { error != nil }, set: { if !$0 { error = nil } }
        )
      ) {
        Button("OK") { error = nil }
      } message: {
        Text(error ?? "")
      }
    }
  }
  private struct ExportDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    var data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws {
      guard let data = configuration.file.regularFileContents else {
        throw AppFailure("Cannot read export file.")
      }
      self.data = data
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
      FileWrapper(regularFileWithContents: data)
    }
  }
#endif
