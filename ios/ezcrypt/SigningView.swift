import SwiftUI
import UniformTypeIdentifiers

private enum Validity: String, CaseIterable, Identifiable {
  case hour = "1 hour"
  case day = "1 day"
  case week = "1 week"
  case year = "1 year"
  case custom = "Custom"
  case forever = "Forever"
  var id: String { rawValue }
  var seconds: TimeInterval? {
    switch self {
    case .hour: 3600
    case .day: 86400
    case .week: 604800
    case .year: 31_536_000
    default: nil
    }
  }
}
struct SigningView: View {
  @Environment(InventoryStore.self) private var store
  @Environment(\.dismiss) private var dismiss
  @Environment(\.dynamicTypeSize) private var typeSize
  let authority: Authority
  @State private var publicKey = ""
  @State private var principalText = ""
  @State private var allPrincipals = false
  @State private var keyID = ""
  @State private var serial = ""
  @State private var start = Date()
  @State private var end = Date().addingTimeInterval(86400)
  @State private var validity = Validity.day
  @State private var enabledPermissions: Set<String> = ["permit-pty"]
  @State private var command = ""
  @State private var source = ""
  @State private var prepared: Prepared?
  @State private var issued: CertificateRecord?
  @State private var recovery: CertificateRecord?
  @State private var error: String?
  @State private var working = false
  @State private var importing = false
  @State private var acknowledgeDuplicate = false

  private var completed: Bool {
    issued != nil
      || recovery.map { recovered in
        store.inventory.certificates.contains { $0.id == recovered.id }
      } == true
  }

  private var request: SigningRequest {
    var critical: [String: String] = [:]
    if !command.isEmpty { critical["force-command"] = command }
    if !source.isEmpty { critical["source-address"] = source }
    return SigningRequest(
      publicKey: publicKey, purpose: authority.purpose, keyID: keyID, serial: serial,
      principals: allPrincipals
        ? []
        : principalText.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init),
      allPrincipals: allPrincipals,
      validAfter: UInt64(max(0, start.timeIntervalSince1970)),
      validBefore: validity == .forever
        ? nil
        : UInt64(
          max(
            0, (validity.seconds.map { start.addingTimeInterval($0) } ?? end).timeIntervalSince1970)
        ),
      criticalOptions: authority.purpose == .user ? critical : [:],
      extensions: authority.purpose == .user
        ? Dictionary(uniqueKeysWithValues: enabledPermissions.map { ($0, "") }) : [:])
  }
  var body: some View {
    Group {
      if let issued {
        CertificateDetail(certificate: issued)
      } else if let recovery {
        PendingCertificateView(certificate: recovery)
      } else if let prepared {
        review(prepared)
      } else {
        editor
      }
    }
    .navigationTitle(
      completed
        ? "Signed"
        : recovery != nil
          ? "Save Certificate"
          : prepared != nil ? "Review" : "Sign Key"
    )
    .navigationBarTitleDisplayMode(.inline)
    .sensoryFeedback(.success, trigger: completed) { _, new in new }
    .toolbar {
      ToolbarItem(placement: .cancellationAction) {
        Button(issued == nil && recovery == nil ? "Cancel" : "Done") { dismiss() }.disabled(
          working || store.busy)
      }
    }
    .interactiveDismissDisabled(working || store.busy)
    .onAppear {
      if serial.isEmpty {
        serial = (store.authority(authority.id)?.nextSerial ?? authority.nextSerial).description
      }
    }
    .fileImporter(isPresented: $importing, allowedContentTypes: [.plainText, .data]) { result in
      do { publicKey = try readPublicFile(result.get(), maximum: 16_384) } catch {
        self.error = error.localizedDescription
      }
    }
  }
  private var validityFooter: String {
    guard let end = request.validBefore else { return "Never expires." }
    return "Expires \(dateLabel(end))."
  }
  private var editor: some View {
    Form {
      Section {
        TextField(
          "Public key", text: $publicKey, prompt: Text("ssh-ed25519 AAAA…"), axis: .vertical
        )
        .font(.footnote.monospaced()).lineLimit(3...6).textInputAutocapitalization(.never)
        .autocorrectionDisabled().accessibilityIdentifier("subject-key")
        if let detected = SubjectKeyKind(publicKey) {
          Label {
            HStack {
              Text(detected.description)
              if let comment = detected.comment {
                Spacer()
                Text(comment).font(.footnote.monospaced()).foregroundStyle(.secondary).lineLimit(1)
              }
            }
          } icon: {
            Image(
              systemName: detected.supported
                ? "checkmark.circle.fill" : "exclamationmark.triangle.fill"
            )
            .foregroundStyle(detected.supported ? .green : .orange)
          }
          .font(.subheadline)
        } else {
          HStack {
            PasteButton(payloadType: String.self) { publicKey = $0.first ?? "" }
            Spacer()
            Button("Choose File", systemImage: "doc") { importing = true }
          }
          .buttonStyle(.borderless).labelStyle(.titleAndIcon)
        }
      } header: {
        Text("Public Key")
      } footer: {
        Text("Ed25519, ECDSA, or FIDO2 security key (sk-) in OpenSSH format.")
      }
      Section {
        if !allPrincipals {
          TextField(
            authority.purpose == .user ? "Usernames" : "Hostnames", text: $principalText,
            prompt: Text(authority.purpose == .user ? "alice, deploy" : "host.example.com")
          )
          .font(.body.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
          .accessibilityIdentifier("principals")
        }
        Toggle(
          authority.purpose == .user ? "All principals (advanced)" : "All principals",
          isOn: $allPrincipals)
      } header: {
        Text(authority.purpose == .user ? "Usernames" : "Hostnames")
      } footer: {
        if allPrincipals {
          Text(
            authority.purpose == .user
              ? "Requires a CA trusted in the account’s authorized_keys without a principals restriction. Servers using TrustedUserCAKeys reject certificates with no principals. Use explicit usernames for that setup."
              : "This certificate will not restrict which hostname it can represent."
          ).foregroundStyle(.orange)
        } else {
          Text("Separate with commas or spaces.")
        }
      }
      Section {
        Picker("Valid for", selection: $validity) {
          ForEach(Validity.allCases) { Text($0.rawValue).tag($0) }
        }.accessibilityIdentifier("validity")
        DatePicker("Starts", selection: $start)
        if validity == .custom { DatePicker("Ends", selection: $end) }
      } header: {
        Text("Validity")
      } footer: {
        Text(validityFooter)
      }
      Section {
        TextField("Key ID", text: $keyID, prompt: Text("Optional")).font(.body.monospaced())
          .textInputAutocapitalization(.never).autocorrectionDisabled()
          .accessibilityIdentifier("key-id")
      } header: {
        Text("Key ID")
      } footer: {
        Text("Logged by the server whenever this certificate is used.")
      }
      Section {
        DisclosureGroup("Advanced") {
          LabeledContent("Serial") {
            TextField("Serial", text: $serial).keyboardType(.numberPad).font(.body.monospaced())
              .multilineTextAlignment(.trailing)
          }
          if authority.purpose == .user {
            ForEach(permissions, id: \.self) { value in
              Toggle(
                permissionLabel(value),
                isOn: Binding(
                  get: { enabledPermissions.contains(value) },
                  set: {
                    if $0 {
                      enabledPermissions.insert(value)
                    } else {
                      enabledPermissions.remove(value)
                    }
                  }))
            }
            TextField("Force command", text: $command, axis: .vertical).font(.body.monospaced())
              .textInputAutocapitalization(.never).autocorrectionDisabled()
            TextField(
              "Source addresses", text: $source, prompt: Text("Source CIDRs, comma separated"),
              axis: .vertical
            )
            .font(.body.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
          }
        }
      } footer: {
        Text(
          "Next available serial: \(store.authority(authority.id)?.nextSerial ?? 1). Serials are reserved before signing."
        )
      }
    }
    .scrollDismissesKeyboard(.interactively)
    .actionBar {
      errorText
      PrimaryButton(title: "Review", busy: working) {
        working = true
        error = nil
        Task {
          defer { working = false }
          do {
            prepared = try await store.prepare(request, authority: authority)
            acknowledgeDuplicate = false
          } catch { self.error = error.localizedDescription }
        }
      }
      .disabled(publicKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
      .accessibilityIdentifier("review-certificate")
    }
  }
  @ViewBuilder private var errorText: some View {
    if let error {
      Text(error).font(.footnote).foregroundStyle(.red).frame(maxWidth: .infinity)
        .accessibilityIdentifier("signing-error")
    }
  }
  private var editButton: some View {
    Button {
      prepared = nil
    } label: {
      Text("Edit").fontWeight(.semibold).padding(.horizontal, 10).padding(.vertical, 4)
        .frame(maxWidth: typeSize.isAccessibilitySize ? .infinity : nil)
    }
    .buttonStyle(.glass).controlSize(.large).disabled(working)
  }
  private func review(_ prepared: Prepared) -> some View {
    let matches = store.duplicates(prepared)
    return List {
      Section("Signing Authority") {
        HStack(spacing: 14) {
          SealTile(fingerprint: authority.fingerprint)
          VStack(alignment: .leading, spacing: 2) {
            Text(authority.name).font(.headline)
            Text(authority.fingerprint).font(.caption.monospaced()).foregroundStyle(.secondary)
              .lineLimit(1).truncationMode(.middle)
          }
        }
        .accessibilityElement(children: .combine)
      }
      if !matches.isEmpty {
        Section {
          Label("Matching certificate already issued", systemImage: "exclamationmark.triangle.fill")
            .font(.headline).foregroundStyle(.orange)
          ForEach(matches) { match in
            NavigationLink {
              CertificateDetail(certificate: match)
            } label: {
              CertificateRow(certificate: match, showsAuthority: false)
            }
          }
          Toggle("Issue another certificate", isOn: $acknowledgeDuplicate).accessibilityIdentifier(
            "allow-duplicate")
        } footer: {
          Text("These certificates are still valid or overlap the requested interval.")
        }
        .accessibilityIdentifier("duplicate-warning")
      }
      RequestInspection(request: prepared.request, subjectFingerprint: prepared.subjectFingerprint)
    }
    .actionBar {
      errorText
      // Side by side normally; stacked, primary first, at accessibility sizes.
      let layout =
        typeSize.isAccessibilitySize
        ? AnyLayout(VStackLayout(spacing: 10)) : AnyLayout(HStackLayout(spacing: 12))
      layout {
        if !typeSize.isAccessibilitySize { editButton }
        PrimaryButton(title: "Sign Certificate", symbol: "faceid", busy: working || store.busy) {
          working = true
          error = nil
          Task {
            defer { working = false }
            do {
              issued = try await store.issue(
                prepared, authorityID: authority.id, allowDuplicate: acknowledgeDuplicate)
            } catch {
              self.error = error.localizedDescription
              if let pending = store.pendingCertificate {
                recovery = pending
                return
              }
              // A failed attempt may have reserved the serial already.
              serial =
                (store.authority(authority.id)?.nextSerial ?? authority.nextSerial).description
              self.prepared = nil
            }
          }
        }
        .disabled(!matches.isEmpty && !acknowledgeDuplicate).accessibilityIdentifier("confirm-sign")
        if typeSize.isAccessibilitySize { editButton }
      }
    }
  }
}
/// Recognizes what was pasted before the core validates it, so mistakes such as
/// a private key or an RSA key are caught while the person is still looking.
struct SubjectKeyKind {
  let description: String
  let supported: Bool
  let comment: String?
  init?(_ text: String) {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }
    if trimmed.hasPrefix("-----BEGIN") {
      (description, supported, comment) = ("Private key. Paste the .pub file instead.", false, nil)
      return
    }
    let fields = trimmed.split(whereSeparator: \.isWhitespace)
    let type = String(fields[0])
    comment = fields.count > 2 ? fields[2...].joined(separator: " ") : nil
    switch type {
    case "ssh-ed25519": (description, supported) = ("Ed25519", true)
    case "ecdsa-sha2-nistp256": (description, supported) = ("ECDSA P-256", true)
    case "ecdsa-sha2-nistp384": (description, supported) = ("ECDSA P-384", true)
    case "ecdsa-sha2-nistp521": (description, supported) = ("ECDSA P-521", true)
    case "sk-ssh-ed25519@openssh.com": (description, supported) = ("Ed25519 security key", true)
    case "sk-ecdsa-sha2-nistp256@openssh.com":
      (description, supported) = ("ECDSA security key", true)
    case "ssh-rsa": (description, supported) = ("RSA keys aren’t supported.", false)
    case _ where type.hasSuffix("-cert-v01@openssh.com"):
      (description, supported) = ("Certificate. Paste the key it certifies instead.", false)
    default: return nil
    }
  }
}
func readPublicFile(_ url: URL, maximum: Int) throws -> String {
  let access = url.startAccessingSecurityScopedResource()
  defer { if access { url.stopAccessingSecurityScopedResource() } }
  let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? maximum + 1
  guard size <= maximum else { throw AppFailure("File is too large.") }
  let data = try Data(contentsOf: url)
  guard data.count <= maximum, let text = String(data: data, encoding: .utf8) else {
    throw AppFailure("Choose a text public-key file.")
  }
  return text
}
