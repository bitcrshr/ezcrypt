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
}
struct AuthoritiesView: View {
  @Environment(InventoryStore.self) private var store
  @State private var sheet: AuthoritySheet?
  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 22) {
        HStack(alignment: .top) {
          VStack(alignment: .leading, spacing: 8) {
            Eyebrow(text: "Your trust, on hand")
            Text("ezcrypt").font(.system(size: 44, weight: .semibold, design: .rounded)).tracking(
              -2)
          }
          Spacer()
          Image(systemName: "key.horizontal").font(.system(size: 28, weight: .medium))
            .foregroundStyle(Ink.accent).frame(width: 66, height: 66).background(
              Ink.accent.opacity(0.1), in: RoundedRectangle(cornerRadius: 22))
        }.padding(.top, 12)
        HStack {
          Eyebrow(text: "Authorities")
          Spacer()
          Text("\(store.authorities.count)").font(.system(.caption, design: .monospaced))
            .foregroundStyle(.secondary)
        }
        if store.authorities.isEmpty {
          Panel {
            Text("A home for your SSH authorities.").font(.title2.weight(.medium))
            Text(
              "Create a user or host CA. Keep its key in hardware, or choose protected software for portable backups."
            ).foregroundStyle(.secondary)
            PrimaryAction(title: "Create authority", symbol: "plus") { sheet = .create }
              .accessibilityIdentifier("create-first-ca")
          }
        } else {
          ForEach(store.authorities) { authority in
            NavigationLink {
              AuthorityDetail(authorityID: authority.id)
            } label: {
              AuthorityCard(
                authority: authority,
                issued: store.certificates.filter { $0.authorityID == authority.id }.count)
            }.buttonStyle(.plain)
          }
        }
        Text("Private keys stay on this device. Certificates go wherever you need them.").font(
          .footnote
        ).foregroundStyle(.secondary).padding(.horizontal, 4)
      }.padding(22)
    }.pageStyle().navigationTitle("Authorities").navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .topBarTrailing) {
          Button("Create authority", systemImage: "plus") { sheet = .create }
            .accessibilityIdentifier("add-ca")
        }
      }
      .sheet(item: $sheet) { _ in NavigationStack { CreateAuthorityView() }.environment(store) }
  }
}
struct AuthorityCard: View {
  let authority: Authority
  let issued: Int
  var body: some View {
    Panel {
      HStack(alignment: .top) {
        Image(systemName: authority.purpose.symbol).font(.title2).foregroundStyle(Ink.accent)
        Spacer()
        Text(authority.algorithm.title).font(.system(.caption, design: .monospaced))
          .foregroundStyle(.secondary)
        Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
      }
      VStack(alignment: .leading, spacing: 5) {
        Text(authority.name).font(.title2.weight(.semibold))
        Text("\(authority.purpose.title) CA · \(authority.custody.title)").font(.subheadline)
          .foregroundStyle(.secondary)
      }
      Divider()
      HStack {
        Text("\(issued) issued").font(.caption)
        Spacer()
        Text(authority.fingerprint.suffix(12)).font(.system(.caption, design: .monospaced))
          .foregroundStyle(.secondary)
      }
    }.accessibilityElement(children: .combine)
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
    ScrollView {
      VStack(alignment: .leading, spacing: 20) {
        Text("Establish an authority.").font(.largeTitle.weight(.semibold))
        Panel {
          Eyebrow(text: "Identity")
          TextField("Name", text: $name).inputStyle().accessibilityIdentifier("ca-name")
          Picker("Purpose", selection: $purpose) {
            ForEach(Purpose.allCases) { Text($0.title).tag($0) }
          }.pickerStyle(.segmented)
        }
        Panel {
          Eyebrow(text: "Key custody")
          ForEach(Custody.allCases) { mode in
            Button {
              custody = mode
            } label: {
              HStack(alignment: .top, spacing: 12) {
                Image(systemName: custody == mode ? "checkmark.circle.fill" : "circle")
                  .foregroundStyle(Ink.accent)
                VStack(alignment: .leading, spacing: 6) {
                  Text(mode.title).fontWeight(.semibold).foregroundStyle(.primary)
                  Text(
                    mode == .enclave
                      ? "P-256, generated in hardware. The private key never leaves this device and cannot be backed up."
                      : "Ed25519 or ECDSA, encrypted under a device hardware key. Export an encrypted backup whenever you need."
                  ).font(.subheadline).foregroundStyle(.secondary)
                }
              }.frame(maxWidth: .infinity, alignment: .leading)
            }.buttonStyle(.plain).accessibilityIdentifier("custody-\(mode.rawValue)")
          }
          if custody == .software {
            Picker("Algorithm", selection: $algorithm) {
              ForEach(KeyAlgorithm.allCases) { Text($0.title).tag($0) }
            }.accessibilityIdentifier("ca-algorithm")
          }
        }
        if let error { Text(error).foregroundStyle(.red).font(.callout) }
        PrimaryAction(title: "Create authority", symbol: "faceid", busy: store.busy) {
          Task {
            do {
              try await store.create(
                name: name, purpose: purpose, custody: custody, algorithm: algorithm)
              dismiss()
            } catch { self.error = error.localizedDescription }
          }
        }.disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
          .accessibilityIdentifier("confirm-create-ca")
      }.padding(22)
    }.pageStyle().navigationTitle("New authority").navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button("Cancel") { dismiss() }.disabled(store.busy)
        }
      }.interactiveDismissDisabled(store.busy)
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
      ScrollView {
        VStack(alignment: .leading, spacing: 20) {
          Panel {
            Label("\(authority.purpose.title) authority", systemImage: authority.purpose.symbol)
              .font(.subheadline).foregroundStyle(Ink.accent)
            Text(authority.name).font(.largeTitle.weight(.semibold))
            Text("\(authority.custody.title) · \(authority.algorithm.title)").foregroundStyle(
              .secondary)
            Fingerprint(value: authority.fingerprint)
            HStack {
              ShareLink(item: authority.publicKey) {
                Label("Public key", systemImage: "square.and.arrow.up")
              }
              Spacer()
              Button("Copy", systemImage: "document.on.document") {
                UIPasteboard.general.string = authority.publicKey
              }
            }
          }
          if !authority.archived {
            PrimaryAction(title: "Sign a public key", symbol: "signature") {
              sheet = .sign(authority)
            }.accessibilityIdentifier("sign-key")
            if authority.custody == .software {
              Button {
                sheet = .export(authority)
              } label: {
                Label("Export encrypted CA key", systemImage: "arrow.up.document").frame(
                  maxWidth: .infinity
                ).padding(14)
              }.accessibilityIdentifier("export-ca")
            }
          }
          HStack {
            Eyebrow(text: "Issued certificates")
            Spacer()
          }
          let certificates = store.certificates.filter { $0.authorityID == authority.id }
          if certificates.isEmpty {
            Text("Certificates issued by this authority will appear here.").foregroundStyle(
              .secondary
            ).padding(.vertical)
          }
          ForEach(certificates) { certificate in
            NavigationLink {
              CertificateDetail(certificate: certificate)
            } label: {
              CertificateRow(certificate: certificate)
            }.buttonStyle(.plain)
          }
          if authority.keyRemovalPending == true {
            Text("Private-key removal was interrupted. Retry to finish removing the device key.")
              .foregroundStyle(.orange)
            Button("Retry key removal", role: .destructive) {
              Task {
                do {
                  try await store.remove(authority)
                  dismiss()
                } catch { store.failure = error.localizedDescription }
              }
            }
          }
          if !authority.archived {
            Button("Remove private CA key", role: .destructive) { confirmRemove = true }.padding(
              .top, 24)
          }
        }.padding(22)
      }.pageStyle().navigationTitle(authority.name).navigationBarTitleDisplayMode(.inline)
        .sheet(item: $sheet) { route in
          NavigationStack {
            switch route {
            case .sign(let a): SigningView(authority: a)
            case .export(let a): ExportView(authority: a)
            case .create: CreateAuthorityView()
            }
          }.environment(store)
        }
        .confirmationDialog(
          "Permanently remove this CA’s private key?", isPresented: $confirmRemove,
          titleVisibility: .visible
        ) {
          Button("Remove private key", role: .destructive) {
            Task {
              do {
                try await store.remove(authority)
                dismiss()
              } catch { store.failure = error.localizedDescription }
            }
          }
        } message: {
          Text(
            "Issued certificates and public history stay in the inventory. Removing a CA does not revoke its certificates.\(authority.custody == .enclave ? " This hardware key cannot be recovered." : " Recovery requires an existing encrypted export.")"
          )
        }
    }
  }
}
