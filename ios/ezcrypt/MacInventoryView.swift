#if os(macOS)
  import SwiftUI

  private enum InventorySection: String, CaseIterable, Identifiable {
    case authorities = "Authorities"
    case certificates = "Certificates"
    var id: Self { self }
    var symbol: String { self == .authorities ? "key.horizontal" : "checkmark.seal" }
  }

  struct MacInventoryView: View {
    @Environment(InventoryStore.self) private var store
    @State private var section: InventorySection? = .authorities
    @State private var authorityID: UUID?
    @State private var certificateID: UUID?
    @State private var query = ""
    @State private var status: CertificateStatus?
    @State private var purpose: Purpose?
    @State private var creating = false
    @State private var authorityVisibility = InventoryVisibility.active
    @State private var certificateVisibility = InventoryVisibility.active

    private var authorities: [Authority] {
      store.visibleAuthorities(authorityVisibility).filter {
        query.isEmpty || $0.name.localizedCaseInsensitiveContains(query)
          || $0.fingerprint.localizedCaseInsensitiveContains(query)
      }
    }
    private var certificates: [CertificateRecord] {
      store.certificates.filter {
        certificateVisibility.includes(archived: $0.isArchived)
          && (query.isEmpty || $0.searchable.localizedCaseInsensitiveContains(query))
          && (status == nil || $0.status(at: store.now) == status)
          && (purpose == nil || $0.payload.request.purpose == purpose)
      }
    }
    private func startCreating() {
      section = .authorities
      authorityVisibility = .active
      query = ""
      creating = true
    }
    private var canCreate: Bool { !store.busy && store.pendingCertificate == nil }
    var body: some View {
      NavigationSplitView {
        List(InventorySection.allCases, selection: $section) { item in
          Label(item.rawValue, systemImage: item.symbol).tag(item)
        }
        .navigationTitle("ezcrypt")
        .navigationSplitViewColumnWidth(min: 160, ideal: 180)
      } content: {
        Group {
          if section == .certificates {
            List(certificates, selection: $certificateID) { certificate in
              CertificateRow(certificate: certificate).tag(certificate.id)
                .contextMenu {
                  CopyButton("Copy Certificate", value: certificate.payload.certificate)
                }
            }
            .overlay {
              if certificates.isEmpty {
                ContentUnavailableView(
                  "No Certificates", systemImage: "checkmark.seal",
                  description: Text(
                    store.certificates.isEmpty
                      ? "Sign a key from an authority to get started."
                      : "No certificates match your search and filters."))
              }
            }
            .toolbar {
              Menu("Filter", systemImage: "line.3.horizontal.decrease") {
                Picker("Inventory", selection: $certificateVisibility) {
                  ForEach(InventoryVisibility.allCases) { Text($0.rawValue).tag($0) }
                }
                Picker("Status", selection: $status) {
                  Text("Any Status").tag(CertificateStatus?.none)
                  ForEach(CertificateStatus.allCases, id: \.self) {
                    Text($0.rawValue).tag(Optional($0))
                  }
                }
                Picker("Type", selection: $purpose) {
                  Text("Users & Hosts").tag(Purpose?.none)
                  ForEach(Purpose.allCases) { Text($0.title).tag(Optional($0)) }
                }
              }
            }
          } else {
            List(authorities, selection: $authorityID) { authority in
              AuthorityRow(
                authority: authority,
                issued: store.certificates.filter { $0.authorityID == authority.id }.count
              )
              .tag(authority.id)
              .contextMenu { CopyButton("Copy Public Key", value: authority.publicKey) }
            }
            .toolbar {
              Menu("Show", systemImage: "line.3.horizontal.decrease") {
                Picker("Inventory", selection: $authorityVisibility) {
                  ForEach(InventoryVisibility.allCases) { Text($0.rawValue).tag($0) }
                }
              }.accessibilityIdentifier("authority-visibility")
            }
            .overlay {
              if authorities.isEmpty {
                ContentUnavailableView {
                  Label(
                    store.inventory.authorities.isEmpty ? "No Authorities" : "No Matches",
                    systemImage: "key.horizontal")
                } description: {
                  Text(
                    store.inventory.authorities.isEmpty
                      ? "Create an authority to sign SSH keys on this Mac."
                      : "Try another name or fingerprint.")
                } actions: {
                  if store.inventory.authorities.isEmpty {
                    Button("Create Authority") { startCreating() }.buttonStyle(.borderedProminent)
                  }
                }
              }
            }
          }
        }
        .navigationTitle(section?.rawValue ?? "Authorities")
        .frame(minWidth: 300)
        .navigationSplitViewColumnWidth(min: 300, ideal: 340, max: 480)
        .searchable(
          text: $query,
          prompt: section == .certificates ? "Search certificates" : "Search authorities")
      } detail: {
        NavigationStack {
          if section == .certificates,
            let certificate = store.certificates.first(where: { $0.id == certificateID })
          {
            CertificateDetail(certificate: certificate).id(certificate.id)
          } else if section != .certificates, let authorityID,
            store.inventory.authorities.contains(where: { $0.id == authorityID })
          {
            AuthorityDetail(authorityID: authorityID).id(authorityID)
          } else {
            ContentUnavailableView(
              "Select an \(section == .certificates ? "Issued Certificate" : "Authority")",
              systemImage: section?.symbol ?? "key.horizontal",
              description: Text("Details and actions appear here."))
          }
        }
        .id(section == .certificates ? certificateID : authorityID)
        .frame(minWidth: 360)
      }
      .navigationSplitViewStyle(.balanced)
      .focusedSceneValue(\.createAuthority, canCreate ? { startCreating() } : nil)
      .toolbar {
        ToolbarItem(placement: .primaryAction) {
          Button("New Authority", systemImage: "plus") { startCreating() }
            .disabled(!canCreate)
            .accessibilityIdentifier("add-ca")
        }
      }
      .onChange(of: section) { query = "" }
      .sheet(isPresented: $creating) {
        NavigationStack { CreateAuthorityView() }.editorSize().environment(store)
      }
    }
  }
  private struct CreateAuthorityAction: FocusedValueKey {
    typealias Value = () -> Void
  }
  extension FocusedValues {
    var createAuthority: (() -> Void)? {
      get { self[CreateAuthorityAction.self] }
      set { self[CreateAuthorityAction.self] = newValue }
    }
  }
  struct MacCommands: Commands {
    @FocusedValue(\.createAuthority) private var createAuthority
    var body: some Commands {
      CommandGroup(after: .newItem) {
        Button("New Authority…") { createAuthority?() }
          .keyboardShortcut("n", modifiers: .command)
          .disabled(createAuthority == nil)
      }
      SidebarCommands()
    }
  }
#endif
