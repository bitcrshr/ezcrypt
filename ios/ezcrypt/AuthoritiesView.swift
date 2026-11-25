import SwiftUI

private enum AuthoritySheet: Identifiable {
  case create
  case sign(Authority)
  case export(Authority)
  var id: String {
    switch self {
    case .create: "create"
    case .sign(let a): "sign-\(a.id)"
    case .export(let a): "export-\(a.id)"
    }
  }
  @MainActor @ViewBuilder var view: some View {
    switch self {
    case .create: CreateAuthorityView()
    case .sign(let a): SigningView(authority: a)
    case .export(let a): ExportView(authority: a)
    }
  }
}
struct AuthoritiesView: View {
  @Environment(InventoryStore.self) private var store
  @Environment(LinkRouter.self) private var router
  @State private var sheet: AuthoritySheet?
  @State private var visibility = InventoryVisibility.active
  var body: some View {
    List {
      ForEach(store.visibleAuthorities(visibility)) { authority in
        NavigationLink {
          AuthorityDetail(authorityID: authority.id)
        } label: {
          AuthorityRow(
            authority: authority,
            issued: store.certificates.filter { $0.authorityID == authority.id }.count)
        }
        .swipeActions(edge: .leading) {
          if !authority.isArchived {
            Button("Sign Key", systemImage: "signature") { sheet = .sign(authority) }.tint(
              Ink.accent)
          }
        }
        .contextMenu {
          if !authority.isArchived {
            Button("Sign Key…", systemImage: "signature") { sheet = .sign(authority) }
          }
          CopyButton("Copy Public Key", value: authority.publicKey)
        }
      }
    }
    .overlay {
      if store.visibleAuthorities(visibility).isEmpty {
        ContentUnavailableView {
          Label(
            visibility == .archived ? "No Archived Authorities" : "No Authorities",
            systemImage: "key.horizontal")
        } description: {
          Text(
            visibility == .archived
              ? "Archived authorities appear here. Restore an authority to sign with it again."
              : "Create a user or host CA to start signing SSH keys.")
        } actions: {
          Button("Create Authority") {
            visibility = .active
            sheet = .create
          }.buttonStyle(.glassProminent)
            .accessibilityIdentifier("create-first-ca")
        }
      }
    }
    .navigationTitle("Authorities")
    .toolbar {
      #if os(iOS)
        ToolbarItem(placement: .topBarLeading) {
          Button("Scan", systemImage: "qrcode.viewfinder") { router.scanning = true }
            .accessibilityIdentifier("scan-link")
        }
      #endif
      ToolbarItem(placement: .primaryAction) {
        Menu("Show", systemImage: "line.3.horizontal.decrease") {
          Picker("Inventory", selection: $visibility) {
            ForEach(InventoryVisibility.allCases) { Text($0.rawValue).tag($0) }
          }
        }.accessibilityIdentifier("authority-visibility")
      }
      ToolbarItem(placement: .primaryAction) {
        Button("Create authority", systemImage: "plus") {
          visibility = .active
          sheet = .create
        }
        .accessibilityIdentifier("add-ca")
      }
    }
    .sheet(item: $sheet) { route in NavigationStack { route.view }.editorSize().environment(store) }
  }
}
struct AuthorityRow: View {
  @Environment(\.dynamicTypeSize) private var typeSize
  let authority: Authority
  let issued: Int
  var body: some View {
    // At accessibility sizes the seal moves above the text, leaving the full width to the name.
    let layout =
      typeSize.isAccessibilitySize
      ? AnyLayout(VStackLayout(alignment: .leading, spacing: 10))
      : AnyLayout(HStackLayout(spacing: 14))
    layout {
      SealTile(fingerprint: authority.fingerprint)
      VStack(alignment: .leading, spacing: 3) {
        Text(authority.name).font(.headline)
        if authority.isArchived {
          Label(
            authority.keyRemovalPending == true
              ? "Removal pending" : authority.archived ? "Key removed" : "Archived",
            systemImage: "archivebox"
          )
          .font(.caption).foregroundStyle(.secondary)
        }
        Text(
          authority.keyRemovalPending == true
            ? "Key removal unfinished" : "\(authority.purpose.title) · \(authority.custody.title)"
        )
        .font(.subheadline).foregroundStyle(
          authority.keyRemovalPending == true ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
      }
      if !typeSize.isAccessibilitySize {
        Spacer(minLength: 8)
        if issued > 0 {
          Text(issued, format: .number).font(.subheadline.monospacedDigit()).foregroundStyle(
            .secondary
          )
          .accessibilityLabel("\(issued) issued")
        }
      }
    }
    .padding(.vertical, 2)
    .accessibilityElement(children: .combine)
  }
}
struct CreateAuthorityView: View {
  @Environment(InventoryStore.self) private var store
  @Environment(\.dismiss) private var dismiss
  @State private var name = ""
  @State private var purpose = Purpose.user
  @State private var custody = Custody.enclave
  @State private var algorithm = KeyAlgorithm.ed25519
  @State private var error: String?
  var body: some View {
    Form {
      Section {
        TextField("Name", text: $name, prompt: Text("Production users")).submitLabel(.done)
          .accessibilityIdentifier("ca-name")
      } header: {
        Text("Name")
      }
      Section {
        Picker("Type", selection: $purpose) {
          ForEach(Purpose.allCases) { Text($0.title).tag($0) }
        }.pickerStyle(.segmented).listRowBackground(Color.clear).listRowInsets(EdgeInsets())
      } header: {
        Text("Type")
      } footer: {
        Text(
          purpose == .user
            ? "Certifies the keys people log in with."
            : "Certifies server host keys, so clients can trust them on first connection.")
      }
      Section("Key Storage") {
        ForEach(Custody.allCases) { mode in
          Button {
            custody = mode
          } label: {
            HStack(spacing: 12) {
              VStack(alignment: .leading, spacing: 3) {
                Text(mode.title).foregroundStyle(.primary)
                Text(
                  mode == .enclave
                    ? "P-256 in hardware. Can’t leave this device or be backed up."
                    : "Encrypted by a device key. Can be exported as a backup."
                ).font(.subheadline).foregroundStyle(.secondary)
              }
              Spacer()
              Image(systemName: "checkmark").fontWeight(.semibold).foregroundStyle(Ink.accent)
                .opacity(custody == mode ? 1 : 0)
            }.contentShape(Rectangle())
          }
          .tint(.primary)
          .accessibilityIdentifier("custody-\(mode.rawValue)")
          .accessibilityAddTraits(custody == mode ? .isSelected : [])
        }
        if custody == .software {
          Picker("Algorithm", selection: $algorithm) {
            ForEach(KeyAlgorithm.allCases) { Text($0.title).tag($0) }
          }.accessibilityIdentifier("ca-algorithm")
        }
      }
    }
    .scrollDismissesKeyboard(.interactively)
    .navigationTitle("New Authority").inlineNavigationTitle()
    .actionBar {
      if let error {
        Text(error).font(.footnote).foregroundStyle(.red).frame(maxWidth: .infinity)
      }
      PrimaryButton(
        title: "Create Authority", symbol: PlatformUI.authenticationSymbol, busy: store.busy
      ) {
        Task {
          do {
            try await store.create(
              name: name, purpose: purpose, custody: custody, algorithm: algorithm)
            dismiss()
          } catch { self.error = error.localizedDescription }
        }
      }
      .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
      .accessibilityIdentifier("confirm-create-ca")
    }
    .toolbar {
      ToolbarItem(placement: .cancellationAction) {
        Button("Cancel") { dismiss() }.disabled(store.busy)
      }
    }
    .interactiveDismissDisabled(store.busy)
  }
}
struct AuthorityDetail: View {
  @Environment(InventoryStore.self) private var store
  @Environment(\.dismiss) private var dismiss
  let authorityID: UUID
  @State private var sheet: AuthoritySheet?
  @State private var confirmRemove = false
  var body: some View {
    if let authority = store.authority(authorityID) {
      let certificates = store.certificates.filter { $0.authorityID == authority.id }
      List {
        Section {
          VStack(spacing: 18) {
            RandomartView(fingerprint: authority.fingerprint, algorithm: authority.algorithm)
            VStack(spacing: 4) {
              Text(authority.name).font(.title2.weight(.semibold)).multilineTextAlignment(.center)
              Text(
                "\(authority.purpose.title) CA · \(authority.custody.title) · \(authority.algorithm.title)"
              )
              .font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            if !authority.isArchived {
              PrimaryButton(title: "Sign Key", symbol: "signature") { sheet = .sign(authority) }
                .accessibilityIdentifier("sign-key")
            }
          }
          .frame(maxWidth: .infinity).listRowBackground(Color.clear)
          .listRowInsets(EdgeInsets(top: 8, leading: 0, bottom: 8, trailing: 0))
        }
        if authority.keyRemovalPending == true {
          Section {
            Button("Retry Key Removal", role: .destructive) {
              Task {
                do {
                  try await store.remove(authority)
                  dismiss()
                } catch { store.failure = error.localizedDescription }
              }
            }
          } footer: {
            Text("Removing the private key was interrupted. Retry to finish.")
          }
        }
        Section {
          TokenBlock(title: "Fingerprint", value: authority.fingerprint)
          CopyButton("Copy Public Key", value: authority.publicKey)
          ShareLink(item: authority.publicKey) {
            Label("Share Public Key", systemImage: "square.and.arrow.up")
          }
        } header: {
          Text("Public Key")
        } footer: {
          Text(
            authority.purpose == .user
              ? "Servers trust this CA through TrustedUserCAKeys in sshd_config."
              : "Clients trust this CA through a @cert-authority line in known_hosts.")
        }
        if !authority.archived && authority.custody == .software {
          Section {
            Button {
              sheet = .export(authority)
            } label: {
              Label("Export Encrypted Backup", systemImage: "arrow.up.document")
            }.accessibilityIdentifier("export-ca")
          }
        }
        Section {
          if certificates.isEmpty {
            Text("None yet").foregroundStyle(.secondary)
          }
          ForEach(certificates) { certificate in
            NavigationLink {
              CertificateDetail(certificate: certificate)
            } label: {
              CertificateRow(certificate: certificate, showsAuthority: false)
            }
          }
        } header: {
          HStack {
            Text("Certificates")
            Spacer()
            if !certificates.isEmpty { Text(certificates.count, format: .number) }
          }
        }
        Section {
          if authority.archived {
            Label(
              authority.keyRemovalPending == true
                ? "Private key removal unfinished" : "Private key removed", systemImage: "key.slash"
            )
          } else {
            Button(
              authority.isArchived ? "Restore Authority" : "Archive Authority",
              systemImage: authority.isArchived ? "arrow.uturn.backward" : "archivebox"
            ) {
              do {
                try store.setAuthorityArchived(authority.id, archived: !authority.isArchived)
                #if !os(macOS)
                  dismiss()
                #endif
              } catch { store.failure = error.localizedDescription }
            }
            .disabled(store.busy || store.pendingCertificate != nil)
            .accessibilityIdentifier("archive-authority")
          }
        } footer: {
          Text(
            authority.keyRemovalPending == true
              ? "Retry key removal to finish. This authority cannot sign or be restored."
              : authority.archived
                ? "Certificate history remains available. The removed private key cannot be restored here."
                : "Archiving keeps the private key and certificate history, and disables new signing until restored. Issued certificates are not revoked."
          )
        }
        if !authority.archived {
          Section {
            Button("Remove Private Key", role: .destructive) { confirmRemove = true }
          }
        }
      }
      .navigationTitle(authority.name).inlineNavigationTitle()
      .toolbar(removing: .title)
      .sheet(item: $sheet) { route in NavigationStack { route.view }.editorSize().environment(store)
      }
      .confirmationDialog(
        "Permanently remove this CA’s private key?", isPresented: $confirmRemove,
        titleVisibility: .visible
      ) {
        Button("Remove Private Key", role: .destructive) {
          Task {
            do {
              try await store.remove(authority)
              dismiss()
            } catch { store.failure = error.localizedDescription }
          }
        }
      } message: {
        Text(
          "Issued certificates stay in the inventory and are not revoked. \(authority.custody == .enclave ? "This hardware key can’t be recovered." : "Recovery requires an existing encrypted backup.")"
        )
      }
    }
  }
}
