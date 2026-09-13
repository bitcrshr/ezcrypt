import SwiftUI
import UniformTypeIdentifiers

struct ExportView: View {
  @Environment(InventoryStore.self) private var store
  @Environment(\.dismiss) private var dismiss
  let authority: Authority
  @State private var useGPG = false
  @State private var password = ""
  @State private var confirmation = ""
  @State private var armor = ""
  @State private var recipient: Recipient?
  @State private var file: URL?
  @State private var error: String?
  @State private var importing = false
  @State private var checking = false
  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 20) {
        Panel {
          Eyebrow(text: "Portable backup")
          Text(authority.name).font(.title.weight(.semibold))
          Fingerprint(value: authority.fingerprint)
          Text("Export an encrypted OpenSSH private key, recoverable without ezcrypt.")
            .foregroundStyle(.secondary)
        }
        if let file {
          Panel {
            Label("Encrypted export ready", systemImage: "checkmark.seal.fill").font(.headline)
              .foregroundStyle(Ink.accent)
            ShareLink(item: file) {
              Label("Save or share backup", systemImage: "square.and.arrow.up").frame(
                maxWidth: .infinity
              ).padding(12)
            }.accessibilityIdentifier("share-backup")
            Text(
              useGPG
                ? "Decrypt with gpg --output ca --decrypt backup.gpg, then chmod 600 ca. The result is an OpenSSH CA private key."
                : "Use directly with ssh-keygen -s, or remove the passphrase with ssh-keygen -p on a trusted computer."
            ).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
          }
        } else {
          Panel {
            Picker("Protect with", selection: $useGPG) {
              Text("Passphrase").tag(false)
              Text("OpenPGP public key").tag(true)
            }.pickerStyle(.segmented)
            if useGPG {
              TextField("-----BEGIN PGP PUBLIC KEY BLOCK-----", text: $armor, axis: .vertical).font(
                .system(.caption, design: .monospaced)
              ).lineLimit(3...5).textInputAutocapitalization(.never).autocorrectionDisabled()
                .inputStyle()
              HStack {
                Button("Choose public key", systemImage: "doc") { importing = true }
                Spacer()
                Button("Inspect") { inspectRecipient() }.disabled(armor.isEmpty || checking)
              }
              if let recipient {
                LabeledValue(title: "Recipient fingerprint", value: recipient.fingerprint)
                LabeledValue(title: "Encryption subkey", value: recipient.subkey)
                Text(
                  "Check this fingerprint against your intended recipient. Only revocations present in the supplied key can be detected."
                ).font(.caption).foregroundStyle(.secondary)
              }
            } else {
              SecureField("Passphrase · 12+ characters", text: $password).textContentType(
                .newPassword
              ).inputStyle().accessibilityIdentifier("export-password")
              SecureField("Repeat passphrase", text: $confirmation).textContentType(.newPassword)
                .inputStyle().accessibilityIdentifier("export-confirmation")
              Text(
                "Use a long, unique passphrase. This backup can recover the CA independently of this device."
              ).font(.caption).foregroundStyle(.secondary)
            }
          }
          if let error { Text(error).foregroundStyle(.red) }
          PrimaryAction(title: "Authenticate & export", symbol: "faceid", busy: store.busy) {
            Task {
              do {
                file = try await store.export(
                  authority: authority, password: password, armor: armor,
                  fingerprint: recipient?.fingerprint ?? "", useGPG: useGPG)
                password = ""
                confirmation = ""
              } catch { self.error = error.localizedDescription }
            }
          }.disabled(
            useGPG ? recipient == nil : password.count < 12 || password != confirmation
          ).accessibilityIdentifier("confirm-export")
        }
      }.padding(22)
    }.pageStyle().navigationTitle("Export CA key").navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button(file == nil ? "Cancel" : "Done") { dismiss() }.disabled(store.busy)
        }
      }
      .interactiveDismissDisabled(store.busy)
      .onChange(of: armor) { recipient = nil }
      .onDisappear {
        password = ""
        confirmation = ""
      }
      .fileImporter(isPresented: $importing, allowedContentTypes: [.plainText, .data]) { result in
        do { armor = try readPublicFile(result.get(), maximum: 256 * 1024) } catch {
          self.error = error.localizedDescription
        }
      }
  }
  private func inspectRecipient() {
    checking = true
    error = nil
    let input = armor
    Task {
      defer { checking = false }
      do {
        let checked = try await store.engine.recipient(input)
        if armor == input { recipient = checked }
      } catch { self.error = error.localizedDescription }
    }
  }
}
