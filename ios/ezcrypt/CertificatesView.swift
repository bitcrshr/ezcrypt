import SwiftUI

struct CertificatesView: View {
  @Environment(InventoryStore.self) private var store
  @State private var query = ""
  @State private var status: CertificateStatus?
  @State private var purpose: Purpose?
  var filtered: [CertificateRecord] {
    store.certificates.filter {
      (query.isEmpty || $0.searchable.localizedCaseInsensitiveContains(query))
        && (status == nil || $0.status(at: store.now) == status)
        && (purpose == nil || $0.payload.request.purpose == purpose)
    }
  }
  var body: some View {
    let filtered = filtered
    List {
      ForEach(CertificateStatus.allCases, id: \.self) { group in
        let members = filtered.filter { $0.status(at: store.now) == group }
        if !members.isEmpty {
          Section {
            ForEach(members) { certificate in
              NavigationLink {
                CertificateDetail(certificate: certificate)
              } label: {
                CertificateRow(certificate: certificate)
              }
              .contextMenu {
                CopyButton("Copy Certificate", value: certificate.payload.certificate)
              }
            }
          } header: {
            HStack {
              Text(group.rawValue)
              Spacer()
              Text(members.count, format: .number)
            }
          }
        }
      }
    }
    .overlay {
      if store.certificates.isEmpty {
        ContentUnavailableView {
          Label("No Certificates", systemImage: "checkmark.seal")
        } description: {
          Text("Certificates you sign from an authority appear here.")
        }
      } else if filtered.isEmpty {
        if query.isEmpty {
          ContentUnavailableView {
            Label("No Matches", systemImage: "line.3.horizontal.decrease")
          } actions: {
            Button("Clear Filters") {
              status = nil
              purpose = nil
            }
          }
        } else {
          ContentUnavailableView.search(text: query)
        }
      }
    }
    .navigationTitle("Certificates")
    .searchable(text: $query, prompt: "Principal, key ID, serial, fingerprint")
    .toolbar {
      ToolbarItem(placement: .topBarTrailing) {
        Menu {
          Picker("Status", selection: $status) {
            Text("Any Status").tag(CertificateStatus?.none)
            ForEach(CertificateStatus.allCases, id: \.self) {
              Label($0.rawValue, systemImage: $0.symbol).tag(Optional($0))
            }
          }
          Picker("Type", selection: $purpose) {
            Text("Users & Hosts").tag(Purpose?.none)
            ForEach(Purpose.allCases) { Text($0.title).tag(Optional($0)) }
          }
        } label: {
          Label(
            "Filter",
            systemImage: status == nil && purpose == nil
              ? "line.3.horizontal.decrease" : "line.3.horizontal.decrease.circle.fill")
        }
      }
    }
  }
}
struct CertificateRow: View {
  @Environment(InventoryStore.self) private var store
  @Environment(\.dynamicTypeSize) private var typeSize
  let certificate: CertificateRecord
  var showsAuthority = true
  var body: some View {
    let request = certificate.payload.request
    let layout =
      typeSize.isAccessibilitySize
      ? AnyLayout(VStackLayout(alignment: .leading, spacing: 4))
      : AnyLayout(HStackLayout(alignment: .firstTextBaseline))
    VStack(alignment: .leading, spacing: 4) {
      layout {
        Text(certificate.title.isEmpty ? "All principals" : certificate.title)
          .font(.body.monospaced().weight(.semibold)).lineLimit(
            typeSize.isAccessibilitySize ? 3 : 1
          )
          // Expired certificates recede, so they read as history among valid ones.
          .foregroundStyle(certificate.status(at: store.now) == .expired ? .secondary : .primary)
        if !typeSize.isAccessibilitySize { Spacer(minLength: 12) }
        Text(validitySummary(request, at: store.now)).font(.footnote)
          .foregroundStyle(validityTint(request, at: store.now))
          .lineLimit(typeSize.isAccessibilitySize ? 2 : 1)
      }
      Text(
        [
          request.allPrincipals ? "any principal" : request.principals.joined(separator: ", "),
          showsAuthority ? certificate.authorityName : nil, "#\(request.serial)",
        ].compactMap { $0 }.joined(separator: " · ")
      )
      .font(.subheadline).foregroundStyle(.secondary).lineLimit(
        typeSize.isAccessibilitySize ? 3 : 1)
    }
    .padding(.vertical, 2)
    .accessibilityElement(children: .combine)
  }
}
struct CertificateDetail: View {
  @Environment(InventoryStore.self) private var store
  let certificate: CertificateRecord
  @State private var file: URL?
  var body: some View {
    let request = certificate.payload.request
    let status = certificate.status(at: store.now)
    List {
      Section {
        VStack(spacing: 10) {
          StatusLabel(status: status)
          Text(certificate.title.isEmpty ? "All principals" : certificate.title)
            .font(.title2.monospaced().weight(.semibold)).multilineTextAlignment(.center)
            .textSelection(.enabled)
          Text(
            "\(request.purpose.title) certificate · \(validitySummary(request, at: store.now))"
          )
          .font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
          HStack(spacing: 12) {
            if let file {
              ShareLink(item: file) {
                Label("Share", systemImage: "square.and.arrow.up").frame(maxWidth: .infinity)
              }.accessibilityIdentifier("share-certificate")
            }
            CopyButton("Copy", value: certificate.payload.certificate, expands: true)
          }
          .labelStyle(.titleAndIcon).buttonStyle(.glass).controlSize(.large).padding(.top, 10)
        }
        .frame(maxWidth: .infinity).listRowBackground(Color.clear)
        .listRowInsets(EdgeInsets(top: 8, leading: 0, bottom: 8, trailing: 0))
      }
      RequestInspection(
        request: request, subjectFingerprint: certificate.payload.subjectFingerprint)
      Section {
        ValueRow(title: "Issued by", value: certificate.authorityName, token: false)
        TokenBlock(title: "CA fingerprint", value: certificate.payload.caFingerprint)
        ValueRow(
          title: "Signed",
          value: certificate.issuedAt.formatted(date: .abbreviated, time: .shortened),
          token: false)
      } header: {
        Text("Authority")
      }
      Section {
        DisclosureGroup("OpenSSH Certificate") {
          Text(certificate.payload.certificate).font(.caption.monospaced()).textSelection(
            .enabled)
        }
      }
    }
    .navigationTitle("Certificate").navigationBarTitleDisplayMode(.inline)
    .task {
      do { file = try store.certificateFile(certificate) } catch {
        store.failure = error.localizedDescription
      }
    }
  }
}

/// Both the signing sheet and the global recovery entry point deliver the
/// persisted result. Retrying only writes the original certificate to disk.
struct PendingCertificateView: View {
  @Environment(InventoryStore.self) private var store
  let certificate: CertificateRecord
  @State private var error: String?
  var body: some View {
    if let saved = store.certificates.first(where: { $0.id == certificate.id }) {
      CertificateDetail(certificate: saved)
    } else {
      List {
        Section {
          Label("Signed, not yet saved", systemImage: "exclamationmark.triangle.fill")
            .font(.headline).foregroundStyle(.orange)
        } footer: {
          Text(
            "The signature is complete. Saving stores this exact certificate without signing again. Keep the app open until it’s saved."
          )
        }
        RequestInspection(
          request: certificate.payload.request,
          subjectFingerprint: certificate.payload.subjectFingerprint)
      }
      .navigationTitle("Save Certificate").navigationBarTitleDisplayMode(.inline)
      .actionBar {
        if let error {
          Text(error).font(.footnote).foregroundStyle(.red).frame(maxWidth: .infinity)
        }
        PrimaryButton(title: "Save Certificate", symbol: "square.and.arrow.down") {
          do {
            try store.savePendingCertificate()
            error = nil
          } catch { self.error = error.localizedDescription }
        }
        .disabled(store.pendingCertificate?.id != certificate.id || store.busy)
        .accessibilityIdentifier("retry-certificate-save")
      }
    }
  }
}
/// The signed (or about to be signed) fields, as sections of a List.
struct RequestInspection: View {
  let request: SigningRequest
  let subjectFingerprint: String
  var body: some View {
    Section {
      if request.allPrincipals {
        Text("Any principal").font(.body.monospaced())
      }
      ForEach(request.principals, id: \.self) { principal in
        Text(principal).font(.body.monospaced()).textSelection(.enabled)
      }
    } header: {
      Text(request.purpose == .user ? "Usernames" : "Hostnames")
    } footer: {
      if request.purpose == .user && request.allPrincipals {
        Text(
          "Not accepted by TrustedUserCAKeys. Requires per-account CA trust in authorized_keys without a principals restriction."
        ).foregroundStyle(.orange)
      }
    }
    Section {
      ValueRow(title: "From", value: dateLabel(request.validAfter), token: false)
      ValueRow(title: "Until", value: dateLabel(request.validBefore), token: false)
    } header: {
      Text("Validity")
    } footer: {
      Text("Times in \(TimeZone.current.identifier). The end time is exclusive.")
    }
    Section {
      ValueRow(title: "Key ID", value: request.keyID.isEmpty ? "None" : request.keyID)
      ValueRow(title: "Serial", value: request.serial)
      TokenBlock(title: "Fingerprint", value: subjectFingerprint)
      DisclosureGroup("Public Key") {
        Text(request.publicKey).font(.caption.monospaced()).textSelection(.enabled)
      }
    } header: {
      Text("Subject Key")
    }
    if request.purpose == .user {
      Section("Permissions") {
        if request.extensions.isEmpty {
          Text("None").foregroundStyle(.secondary)
        }
        ForEach(request.extensions.keys.sorted(), id: \.self) { name in
          Label(permissionLabel(name), systemImage: "checkmark")
        }
        ForEach(request.criticalOptions.keys.sorted(), id: \.self) { name in
          ValueRow(title: optionLabel(name), value: request.criticalOptions[name] ?? "")
        }
      }
    }
  }
}
let permissions = [
  "permit-pty", "permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding",
  "permit-user-rc",
]
func permissionLabel(_ value: String) -> String {
  switch value {
  case "permit-pty": "Terminal (PTY)"
  case "permit-port-forwarding": "Port forwarding"
  case "permit-agent-forwarding": "Agent forwarding"
  case "permit-X11-forwarding": "X11 forwarding"
  case "permit-user-rc": "User rc"
  default: value
  }
}
func optionLabel(_ value: String) -> String {
  switch value {
  case "force-command": "Force command"
  case "source-address": "Source addresses"
  default: value
  }
}
