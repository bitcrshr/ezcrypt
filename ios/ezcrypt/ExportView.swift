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
  private var ready: Bool {
    useGPG ? recipient != nil : password.count >= 12 && password == confirmation
  }
  var body: some View {
    Group {
      if let file { exported(file) } else { form }
    }
    .navigationTitle(file == nil ? "Export Backup" : "Backup Ready")
    .inlineNavigationTitle()
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
  private var form: some View {
    Form {
      Section {
        Picker("Protect with", selection: $useGPG) {
          Text("Passphrase").tag(false)
          Text("OpenPGP Key").tag(true)
        }.pickerStyle(.segmented).listRowBackground(Color.clear).listRowInsets(EdgeInsets())
      } footer: {
        Text(
          "Exports \(authority.name)’s private key as an encrypted OpenSSH key, usable with ssh-keygen on any computer."
        )
      }
      if useGPG {
        Section {
          TextField(
            "Public key", text: $armor, prompt: Text("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
            axis: .vertical
          )
          .font(.footnote.monospaced()).lineLimit(3...6).verbatimInput()
          .autocorrectionDisabled().accessibilityIdentifier("export-recipient")
          HStack {
            Button("Choose File", systemImage: "doc") { importing = true }
            Spacer()
            if checking {
              ProgressView()
            } else {
              Button("Check Key") { inspectRecipient() }.fontWeight(.semibold).disabled(
                armor.isEmpty || recipient != nil)
            }
          }
          .buttonStyle(.borderless)
        } header: {
          Text("Recipient")
        }
        if let recipient {
          Section {
            TokenBlock(title: "Primary key", value: recipient.fingerprint)
            TokenBlock(title: "Encryption subkey", value: recipient.subkey)
          } footer: {
            Text(
              "Confirm this fingerprint with the key’s owner. Only revocations included in the supplied key are detected."
            )
          }
        }
      } else {
        Section {
          SecureField("Passphrase", text: $password).textContentType(.newPassword)
            .accessibilityIdentifier("export-password")
          SecureField("Repeat passphrase", text: $confirmation).textContentType(.newPassword)
            .accessibilityIdentifier("export-confirmation")
        } footer: {
          VStack(alignment: .leading, spacing: 4) {
            Requirement(text: "At least 12 characters", met: password.count >= 12)
            Requirement(
              text: "Passphrases match", met: !confirmation.isEmpty && password == confirmation)
          }
        }
      }
    }
    .disabled(store.busy)
    .scrollDismissesKeyboard(.interactively)
    .actionBar {
      if let error {
        Text(error).font(.footnote).foregroundStyle(.red).frame(maxWidth: .infinity)
      }
      PrimaryButton(title: "Export", symbol: PlatformUI.authenticationSymbol, busy: store.busy) {
        Task {
          do {
            file = try await store.export(
              authority: authority, password: password, armor: armor,
              fingerprint: recipient?.fingerprint ?? "", useGPG: useGPG)
            password = ""
            confirmation = ""
            error = nil
          } catch { self.error = error.localizedDescription }
        }
      }
      .disabled(!ready).accessibilityIdentifier("confirm-export")
    }
  }
  private func exported(_ file: URL) -> some View {
    let armored = file.pathExtension == "asc"
    return List {
      Section {
        VStack(spacing: 8) {
          Image(systemName: "checkmark.circle.fill").font(.system(size: 44)).foregroundStyle(
            .green
          )
          .symbolEffect(.bounce, value: file)
          Text(armored ? "OpenPGP-encrypted backup" : "Passphrase-encrypted backup").font(
            .headline)
          Text(authority.name).font(.subheadline).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity).listRowBackground(Color.clear)
      }
      if armored {
        Section {
          CopyButton(
            "Copy encrypted backup", value: { try String(contentsOf: file, encoding: .utf8) },
            onError: { error = $0.localizedDescription }
          )
          .accessibilityIdentifier("copy-backup")
        } footer: {
          if let error { Text(error).foregroundStyle(.red) }
        }
      }
      Section {
        Text(
          armored
            ? "gpg --output ca.key --decrypt backup.asc\nchmod 600 ca.key\nssh-keygen -y -f ca.key"
            : "chmod 600 backup.key\nssh-keygen -y -f backup.key"
        )
        .font(.footnote.monospaced()).textSelection(.enabled)
      } header: {
        Text("Recover on a Computer")
      } footer: {
        Text(
          armored
            ? "Save the backup as backup.asc. The decrypted file is the CA’s OpenSSH private key."
            : "Save the backup as backup.key. Use it directly with ssh-keygen -s, or remove the passphrase with ssh-keygen -p."
        )
      }
    }
    .sensoryFeedback(.success, trigger: file)
    .actionBar {
      #if os(macOS)
        SaveFileButton(file: file, title: "Save Backup…").buttonStyle(.borderedProminent)
      #endif
      ShareLink(item: file) {
        Label("Save or Share Backup", systemImage: "square.and.arrow.up").fontWeight(.semibold)
          .foregroundStyle(Ink.onAccent).frame(maxWidth: .infinity).padding(.vertical, 4)
      }
      .buttonStyle(.glassProminent).controlSize(.large).accessibilityIdentifier("share-backup")
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
private struct Requirement: View {
  let text: String
  let met: Bool
  var body: some View {
    Label(text, systemImage: met ? "checkmark.circle.fill" : "circle")
      .foregroundStyle(met ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
      .contentTransition(.symbolEffect(.replace))
  }
}
