import SwiftUI

@main
struct EzcryptApp: App {
  @State private var store = InventoryStore()
  @Environment(\.scenePhase) private var phase
  var body: some Scene {
    WindowGroup {
      AppView().environment(store).tint(Ink.accent)
        .overlay {
          if phase != .active {
            Ink.canvas.ignoresSafeArea().overlay {
              Image(systemName: "key.horizontal").font(.largeTitle).foregroundStyle(Ink.accent)
            }
          }
        }
    }
  }
}
struct AppView: View {
  @Environment(InventoryStore.self) private var store
  var body: some View {
    @Bindable var store = store
    VStack(spacing: 0) {
      DemoBanner()
      if let error = store.loadFailure {
        ContentUnavailableView {
          Label("Inventory unavailable", systemImage: "externaldrive.badge.exclamationmark")
        } description: {
          Text(error)
        }
      } else {
        TabView {
          Tab("Authorities", systemImage: "key.horizontal") {
            NavigationStack { AuthoritiesView() }
          }
          Tab("Certificates", systemImage: "checkmark.seal") {
            NavigationStack { CertificatesView() }
          }
        }
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
      if store.pendingCertificate != nil {
        Button("Certificate signed. Tap to retry saving.") {
          do { try store.savePendingCertificate() } catch {
            store.failure = error.localizedDescription
          }
        }
        .padding().frame(maxWidth: .infinity).background(Color.orange.opacity(0.2))
      }
    }
  }
}
