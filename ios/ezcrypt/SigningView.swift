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
      } else {
        ScrollView {
          VStack(alignment: .leading, spacing: 20) {
            if let prepared { review(prepared) } else { editor }
            if let error {
              Text(error).foregroundStyle(.red).font(.callout).accessibilityIdentifier(
                "signing-error")
            }
          }.padding(22)
        }.pageStyle()
      }
    }.navigationTitle(
      completed
        ? "Certificate issued"
        : recovery != nil
          ? "Save signed certificate"
          : prepared != nil ? "Review certificate" : "Sign with \(authority.name)"
    )
    .navigationBarTitleDisplayMode(.inline)
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
  private var editor: some View {
    Group {
      Panel {
        Eyebrow(text: "Public key")
        TextField("ssh-ed25519 AAAA…", text: $publicKey, axis: .vertical).font(
          .system(.caption, design: .monospaced)
        ).lineLimit(3...6).textInputAutocapitalization(.never).autocorrectionDisabled().inputStyle()
          .accessibilityIdentifier("subject-key")
        HStack {
          PasteButton(payloadType: String.self) { publicKey = $0.first ?? "" }.buttonBorderShape(
            .capsule)
          Spacer()
          Button("Choose file", systemImage: "doc") { importing = true }
        }
        Text("Ed25519, ECDSA, and FIDO2 security-key public keys (ed25519-sk or ecdsa-sk).")
          .font(.caption).foregroundStyle(.secondary)
      }
      Panel {
        Eyebrow(text: authority.purpose == .user ? "Usernames" : "Hostnames")
        if !allPrincipals {
          TextField(
            authority.purpose == .user ? "alice, deploy" : "host.example.com", text: $principalText
          ).textInputAutocapitalization(.never).autocorrectionDisabled().inputStyle()
            .accessibilityIdentifier("principals")
        }
        Toggle(
          authority.purpose == .user ? "All principals (advanced)" : "All principals",
          isOn: $allPrincipals)
        if allPrincipals {
          Text(
            authority.purpose == .user
              ? "Requires a CA trusted in the account’s authorized_keys without a principals restriction. Servers using TrustedUserCAKeys reject certificates with no principals. Use explicit usernames for that setup."
              : "This certificate will not restrict which hostname it can represent."
          ).font(
            .caption
          ).foregroundStyle(.orange)
        }
      }
      Panel {
        Eyebrow(text: "Validity")
        Picker("Valid for", selection: $validity) {
          ForEach(Validity.allCases) { Text($0.rawValue).tag($0) }
        }.accessibilityIdentifier("validity")
        DatePicker("Starts", selection: $start)
        if validity == .custom { DatePicker("Ends", selection: $end) }
        if validity == .forever {
          Label("No expiration", systemImage: "infinity").foregroundStyle(Ink.accent)
        }
      }
      Panel {
        Eyebrow(text: "Identification")
        TextField("Key ID (optional)", text: $keyID).textInputAutocapitalization(.never)
          .autocorrectionDisabled().inputStyle().accessibilityIdentifier("key-id")
        DisclosureGroup("Advanced parameters") {
          VStack(alignment: .leading, spacing: 16) {
            TextField("Serial", text: $serial).keyboardType(.numberPad).inputStyle()
            Text(
              "Next available: \(store.authority(authority.id)?.nextSerial ?? 1). Serials are reserved before signing."
            ).font(.caption).foregroundStyle(.secondary)
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
              TextField("Force command", text: $command, axis: .vertical)
                .textInputAutocapitalization(.never).autocorrectionDisabled().inputStyle()
              TextField("Source CIDRs, comma separated", text: $source, axis: .vertical)
                .textInputAutocapitalization(.never).autocorrectionDisabled().inputStyle()
            }
          }.padding(.top, 16)
        }
      }
      PrimaryAction(title: "Review certificate", busy: working) {
        working = true
        error = nil
        Task {
          defer { working = false }
          do {
            prepared = try await store.prepare(request, authority: authority)
            acknowledgeDuplicate = false
          } catch { self.error = error.localizedDescription }
        }
      }.accessibilityIdentifier("review-certificate")
    }
  }
  private func review(_ prepared: Prepared) -> some View {
    let matches = store.duplicates(prepared)
    return Group {
      Panel {
        Eyebrow(text: "Signing authority")
        Text(authority.name).font(.title2.weight(.semibold))
        Fingerprint(value: authority.fingerprint)
      }
      RequestInspection(request: prepared.request, subjectFingerprint: prepared.subjectFingerprint)
      if !matches.isEmpty {
        Panel {
          Label("Matching certificate already issued", systemImage: "exclamationmark.triangle")
            .font(.headline).foregroundStyle(.orange)
          Text("These certificates are still valid or overlap the requested interval.").font(
            .subheadline
          ).foregroundStyle(.secondary)
          ForEach(matches) { match in
            NavigationLink {
              CertificateDetail(certificate: match)
            } label: {
              Text("\(match.title) · #\(match.payload.request.serial)")
            }
          }
          Toggle("Issue another certificate", isOn: $acknowledgeDuplicate).accessibilityIdentifier(
            "allow-duplicate")
        }.accessibilityIdentifier("duplicate-warning")
      }
      PrimaryAction(title: "Authenticate & sign", symbol: "signature", busy: working || store.busy)
      {
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
            serial = (store.authority(authority.id)?.nextSerial ?? authority.nextSerial).description
            self.prepared = nil
          }
        }
      }.disabled(!matches.isEmpty && !acknowledgeDuplicate).accessibilityIdentifier("confirm-sign")
      Button("Edit parameters") { self.prepared = nil }.frame(maxWidth: .infinity).disabled(working)
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
