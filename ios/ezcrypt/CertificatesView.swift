import SwiftUI

struct CertificatesView: View {
  @Environment(InventoryStore.self) private var store
  @State private var query = ""
  @State private var status = "All"
  @State private var purpose = "All"
  var filtered: [CertificateRecord] {
    store.certificates.filter {
      (query.isEmpty || $0.searchable.localizedCaseInsensitiveContains(query))
        && (status == "All" || $0.status.rawValue == status)
        && (purpose == "All" || $0.payload.request.purpose.title == purpose)
    }
  }
  var body: some View {
    ScrollView {
      LazyVStack(alignment: .leading, spacing: 16) {
        HStack {
          Menu {
            Picker("Status", selection: $status) {
              Text("All").tag("All")
              ForEach(CertificateStatus.allCases, id: \.rawValue) {
                Text($0.rawValue).tag($0.rawValue)
              }
            }
          } label: {
            Label(
              status == "All" ? "All statuses" : status, systemImage: "line.3.horizontal.decrease")
          }
          Spacer()
          Menu {
            Picker("Purpose", selection: $purpose) {
              Text("All").tag("All")
              ForEach(Purpose.allCases) { Text($0.title).tag($0.title) }
            }
          } label: {
            Text(purpose == "All" ? "Users & hosts" : purpose)
          }
        }.font(.subheadline)
        HStack {
          Eyebrow(text: "Certificate inventory")
          Spacer()
          Text("\(filtered.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
        }
        if filtered.isEmpty {
          ContentUnavailableView {
            Label(
              store.certificates.isEmpty ? "Nothing issued yet" : "No matches",
              systemImage: "checkmark.seal")
          } description: {
            Text(
              store.certificates.isEmpty
                ? "Sign a public key from an authority to start your certificate inventory."
                : "Try a principal, key ID, serial, CA name, or fingerprint.")
          }
        }
        ForEach(filtered) { certificate in
          NavigationLink {
            CertificateDetail(certificate: certificate)
          } label: {
            CertificateRow(certificate: certificate)
          }.buttonStyle(.plain)
        }
      }.padding(22)
    }.pageStyle().navigationTitle("Certificates").searchable(
      text: $query, prompt: "Principal, key ID, fingerprint…")
  }
}
struct CertificateRow: View {
  let certificate: CertificateRecord
  var body: some View {
    Panel {
      HStack(alignment: .firstTextBaseline) {
        Text(certificate.title.isEmpty ? "All principals" : certificate.title).font(.headline)
        Spacer()
        StatusPill(status: certificate.status)
      }
      Text(
        certificate.payload.request.principals.isEmpty
          ? "All principals" : certificate.payload.request.principals.joined(separator: ", ")
      ).font(.subheadline).foregroundStyle(.secondary)
      HStack {
        Text(certificate.authorityName)
        Spacer()
        Text("#\(certificate.payload.request.serial)").monospaced()
      }.font(.caption).foregroundStyle(.secondary)
      Text(
        certificate.payload.request.validBefore == nil
          ? "No expiration" : "Until \(dateLabel(certificate.payload.request.validBefore))"
      ).font(.caption).foregroundStyle(
        certificate.payload.request.validBefore == nil ? Ink.accent : .secondary)
    }.accessibilityElement(children: .combine)
  }
}
struct CertificateDetail: View {
  @Environment(InventoryStore.self) private var store
  let certificate: CertificateRecord
  @State private var file: URL?
  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 20) {
        Panel {
          HStack {
            Eyebrow(text: "\(certificate.payload.request.purpose.title) certificate")
            Spacer()
            StatusPill(status: certificate.status)
          }
          Text(certificate.title.isEmpty ? "All principals" : certificate.title).font(
            .title.weight(.semibold))
          LabeledValue(title: "Issued by", value: certificate.authorityName)
          Fingerprint(value: certificate.payload.caFingerprint)
          HStack {
            if let file {
              ShareLink(item: file) {
                Label("Share certificate", systemImage: "square.and.arrow.up")
              }.accessibilityIdentifier("share-certificate")
            }
            Spacer()
            Button("Copy", systemImage: "document.on.document") {
              UIPasteboard.general.string = certificate.payload.certificate
            }
          }
        }
        RequestInspection(
          request: certificate.payload.request,
          subjectFingerprint: certificate.payload.subjectFingerprint)
        Panel {
          Eyebrow(text: "Recorded")
          Text(certificate.issuedAt.formatted(date: .abbreviated, time: .standard)).font(
            .subheadline)
          DisclosureGroup("OpenSSH certificate") {
            Text(certificate.payload.certificate).font(.system(.caption2, design: .monospaced))
              .textSelection(.enabled).padding(.top, 8)
          }
        }
      }.padding(22)
    }.pageStyle().navigationTitle("Certificate").navigationBarTitleDisplayMode(.inline)
      .task {
        do { file = try store.certificateFile(certificate) } catch {
          store.failure = error.localizedDescription
        }
      }
  }
}
struct RequestInspection: View {
  let request: SigningRequest
  let subjectFingerprint: String
  var body: some View {
    Panel {
      Eyebrow(text: "Subject & validity")
      Fingerprint(value: subjectFingerprint)
      DisclosureGroup("Subject public key") {
        Text(request.publicKey).font(.system(.caption, design: .monospaced)).textSelection(
          .enabled)
      }
      LabeledValue(
        title: "Principals",
        value: request.allPrincipals
          ? "All principals" : request.principals.joined(separator: ", "))
      LabeledValue(title: "Key ID", value: request.keyID.isEmpty ? "None" : request.keyID)
      LabeledValue(title: "Serial", value: request.serial)
      Divider()
      LabeledValue(title: "Valid from", value: dateLabel(request.validAfter))
      LabeledValue(title: "Valid until", value: dateLabel(request.validBefore))
      Text("Times shown in \(TimeZone.current.identifier). The end time is exclusive.").font(
        .caption
      ).foregroundStyle(.secondary)
    }
    if request.purpose == .user {
      Panel {
        Eyebrow(text: "Permissions & restrictions")
        if request.extensions.isEmpty {
          Text("No optional permissions").foregroundStyle(.secondary)
        }
        ForEach(request.extensions.keys.sorted(), id: \.self) { name in
          Label(permissionLabel(name), systemImage: "checkmark").font(.subheadline)
        }
        ForEach(request.criticalOptions.keys.sorted(), id: \.self) { name in
          LabeledValue(title: name, value: request.criticalOptions[name] ?? "")
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
