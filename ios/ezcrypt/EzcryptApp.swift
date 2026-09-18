import SwiftUI

@main
struct EzcryptApp: App {
  @State private var store = InventoryStore()
  @Environment(\.scenePhase) private var phase
  var body: some Scene {
    #if os(macOS)
      Window("ezcrypt", id: "inventory") {
        content.frame(minWidth: 900, minHeight: 600)
      }
      .defaultSize(width: 1120, height: 760)
      .commands { MacCommands() }
    #else
      WindowGroup { content }
    #endif
  }
  private var content: some View {
    AppView().environment(store).tint(Ink.accent)
      .task(id: phase) {
        guard phase == .active else { return }
        if store.loadFailure != nil { store.reload() }
        while !Task.isCancelled {
          store.updateClock()
          do { try await Task.sleep(for: .seconds(1)) } catch { return }
        }
      }
      #if !os(macOS)
        .overlay {
          if phase != .active {
            PlatformUI.background.ignoresSafeArea().overlay {
              Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.tertiary)
            }
          }
        }
      #endif
  }
}
struct AppView: View {
  @Environment(InventoryStore.self) private var store
  @State private var recovery: CertificateRecord?
  var body: some View {
    @Bindable var store = store
    VStack(spacing: 0) {
      DemoBanner()
      if let error = store.loadFailure {
        ContentUnavailableView {
          Label("Inventory unavailable", systemImage: "externaldrive.badge.exclamationmark")
        } description: {
          Text(error)
        } actions: {
          Button("Retry loading inventory") { store.reload() }
            .accessibilityIdentifier("retry-inventory")
        }
      } else {
        #if os(macOS)
          MacInventoryView()
        #else
          TabView {
            Tab("Authorities", systemImage: "key.horizontal") {
              NavigationStack { AuthoritiesView() }
            }
            Tab("Certificates", systemImage: "checkmark.seal") {
              NavigationStack { CertificatesView() }
            }
          }
        #endif
      }
    }
    .alert(
      "Operation couldn’t finish",
      isPresented: Binding(get: { store.failure != nil }, set: { if !$0 { store.failure = nil } })
    ) {
      Button("OK") { store.failure = nil }
    } message: {
      Text(store.failure ?? "")
    }
    .safeAreaInset(edge: .top) {
      if let pending = store.pendingCertificate {
        Button {
          recovery = pending
        } label: {
          HStack {
            Label("Signed certificate not saved", systemImage: "exclamationmark.triangle.fill")
            Spacer()
            Text("Finish").fontWeight(.semibold)
          }
          .font(.subheadline).foregroundStyle(.orange).padding(.horizontal, 20).padding(
            .vertical, 12
          )
          .background(Color.orange.opacity(0.12))
        }
      }
    }
    .sheet(item: $recovery) { certificate in
      NavigationStack {
        PendingCertificateView(certificate: certificate)
          .toolbar {
            ToolbarItem(placement: .cancellationAction) {
              Button("Done") { recovery = nil }
            }
          }
      }.editorSize().environment(store)
    }
  }
}
