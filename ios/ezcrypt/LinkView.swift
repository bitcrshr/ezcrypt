import SwiftUI

/// The app-wide link sheet: the scanner, then the offer it found. Deep links
/// open straight to the offer.
struct LinkSheet: View {
  @Environment(LinkRouter.self) private var router
  var body: some View {
    NavigationStack {
      if let offer = router.offer {
        // A new offer starts over, cancelling any delivery to the old one.
        LinkView(offer: offer).id(offer.id)
      } else {
        ScanView()
      }
    }
    .editorSize()
    .linkErrorAlert(router, when: true)
  }
}

extension View {
  func linkErrorAlert(_ router: LinkRouter, when shown: Bool) -> some View {
    alert(
      "Can’t open this link",
      isPresented: Binding(
        get: { shown && router.error != nil }, set: { if !$0 { router.error = nil } })
    ) {
      Button("OK") { router.error = nil }
    } message: {
      Text(router.error ?? "")
    }
  }
}

/// Who is asking, and what. Shown above every step of an offer.
struct OfferHeader: View {
  let offer: LinkOffer
  var body: some View {
    VStack(spacing: 6) {
      Image(systemName: offer.kind == .trust ? "checkmark.shield" : "person.badge.key")
        .font(.system(size: 40)).foregroundStyle(Ink.accent)
      Text(
        offer.kind == .trust ? "Trust a user CA on \(offer.host)" : "Sign a key for \(offer.host)"
      )
      .font(.title3.weight(.semibold)).multilineTextAlignment(.center)
      Text(verbatim: "\(offer.user)@\(offer.host)").font(.subheadline.monospaced())
        .foregroundStyle(.secondary).textSelection(.enabled)
    }
    .frame(maxWidth: .infinity).padding(.vertical, 8)
  }
}

struct LinkView: View {
  @Environment(InventoryStore.self) private var store
  @Environment(LinkRouter.self) private var router
  let offer: LinkOffer
  @State private var selection: UUID?
  @State private var payload: LinkPayload?
  @State private var creating = false
  var body: some View {
    Group {
      if let payload {
        DeliveryView(offer: offer, payload: payload)
      } else if offer.kind == .trust {
        trust
      } else {
        List {
          Section { OfferHeader(offer: offer).listRowBackground(Color.clear) }
          Section {
            Text("This version of ezcrypt can’t sign keys from a link yet.")
              .foregroundStyle(.secondary)
          }
        }
      }
    }
    .navigationTitle(offer.kind == .trust ? "Trust CA" : "Sign Key").inlineNavigationTitle()
    .toolbar {
      ToolbarItem(placement: .cancellationAction) {
        Button(payload == nil ? "Cancel" : "Close") { router.close() }
          .accessibilityIdentifier("close-link")
      }
    }
    .sheet(isPresented: $creating) {
      NavigationStack { CreateAuthorityView() }.editorSize().environment(store)
    }
  }
  @ViewBuilder private var trust: some View {
    let authorities = store.linkAuthorities(.trust)
    List {
      Section { OfferHeader(offer: offer).listRowBackground(Color.clear) }
      if !authorities.isEmpty {
        Section {
          ForEach(authorities) { authority in
            Button {
              selection = authority.id
            } label: {
              HStack(spacing: 12) {
                AuthorityRow(authority: authority, issued: 0)
                Image(systemName: "checkmark").fontWeight(.semibold).foregroundStyle(Ink.accent)
                  .opacity(selection == authority.id ? 1 : 0)
              }
              .contentShape(Rectangle())
            }
            .tint(.primary)
            .accessibilityIdentifier("link-authority")
            .accessibilityAddTraits(selection == authority.id ? .isSelected : [])
          }
        } header: {
          Text("User CA")
        } footer: {
          Text(
            "\(offer.host) will accept certificates from this CA for SSH logins. Only its public key is sent."
          )
        }
      }
    }
    .overlay {
      if authorities.isEmpty {
        ContentUnavailableView {
          Label("No User CA", systemImage: "key.horizontal")
        } description: {
          Text("\(offer.host) needs a user CA to trust. Create one, then send its public key.")
        } actions: {
          Button("Create Authority") { creating = true }.buttonStyle(.glassProminent)
            .accessibilityIdentifier("link-create-ca")
        }
      }
    }
    .actionBar {
      if !authorities.isEmpty {
        PrimaryButton(title: "Send", symbol: "paperplane") {
          guard let authority = authorities.first(where: { $0.id == selection }) else { return }
          payload = .caKey(publicKey: authority.publicKey, name: authority.name)
        }
        .disabled(selection.map { id in !authorities.contains { $0.id == id } } ?? true)
        .accessibilityIdentifier("link-send")
      }
    }
  }
}

/// Sends a payload to the machine, with a paste fallback that works without
/// any network. Leaving this view cancels the delivery.
struct DeliveryView: View {
  private enum Route: Hashable {
    case deliver(attempt: Int)
    case paste
  }
  private enum Status: Equatable {
    case sending, waiting
    case delivered(String)
    case failed(String)
  }
  let offer: LinkOffer
  let payload: LinkPayload
  @State private var route = Route.deliver(attempt: 0)
  @State private var status = Status.sending
  @State private var reply: String?
  @State private var replyError: String?
  init(offer: LinkOffer, payload: LinkPayload) {
    self.offer = offer
    self.payload = payload
  }
  var body: some View {
    List {
      Section { OfferHeader(offer: offer).listRowBackground(Color.clear) }
      if route == .paste, let reply {
        Section {
          // Grouped so lines break between groups: wrapping a single long token
          // inserts hyphens, which base64url also contains. Copied, it is the
          // ungrouped text; the terminal ignores spaces if the groups are pasted.
          Text(verbatim: Self.grouped(reply)).font(.footnote.monospaced())
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityIdentifier("reply-text")
          CopyButton("Copy Again", value: reply)
        } header: {
          Text("Paste this into the waiting terminal.")
        } footer: {
          Text("Copied. The reply only works for this request.")
        }
      } else {
        Section { state }
      }
    }
    .actionBar {
      if let replyError {
        Text(replyError).font(.footnote).foregroundStyle(.red).frame(maxWidth: .infinity)
      }
      if route != .paste && !isDelivered {
        Button("Copy instead", systemImage: "document.on.document") { copyInstead() }
          .buttonStyle(.glass).controlSize(.large).accessibilityIdentifier("copy-instead")
      }
    }
    .task(id: route) { await deliver() }
    .sensoryFeedback(.success, trigger: isDelivered) { _, new in new }
  }
  private var isDelivered: Bool {
    if case .delivered = status { true } else { false }
  }
  @ViewBuilder private var state: some View {
    switch status {
    case .sending, .waiting:
      HStack(spacing: 12) {
        ProgressView()
        VStack(alignment: .leading, spacing: 3) {
          Text(
            status == .sending
              ? "Sending to \(offer.host)…" : "Waiting for confirmation on \(offer.host)")
          if status == .waiting {
            Text("Approve the request in the terminal, or copy the reply instead.")
              .font(.subheadline).foregroundStyle(.secondary)
          }
        }
      }
      .accessibilityElement(children: .combine)
      .accessibilityIdentifier("delivery-status")
    case .delivered(let message):
      Label {
        VStack(alignment: .leading, spacing: 3) {
          Text("Done").fontWeight(.semibold)
          Text(message).font(.subheadline).foregroundStyle(.secondary)
        }
      } icon: {
        Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
      }
      .accessibilityIdentifier("delivery-status")
    case .failed(let message):
      Label {
        Text(message)
      } icon: {
        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
      }
      .accessibilityIdentifier("delivery-status")
      Button("Try Again", systemImage: "arrow.clockwise") {
        if case .deliver(let attempt) = route { route = .deliver(attempt: attempt + 1) }
      }
      .accessibilityIdentifier("delivery-retry")
    }
  }
  private func deliver() async {
    guard route != .paste else { return }
    status = .sending
    // The core doesn't report a connection, so after a moment assume the
    // machine has the request and is asking its user.
    let waiting = Task {
      try? await Task.sleep(for: .seconds(2))
      if !Task.isCancelled && status == .sending { status = .waiting }
    }
    defer { waiting.cancel() }
    do {
      let outcome = try await Link.deliver(offer, payload)
      guard !Task.isCancelled else { return }
      status = outcome.ok ? .delivered(outcome.message) : .failed(outcome.message)
    } catch is CancellationError {
      // Closed, or switched to pasting.
    } catch {
      if !Task.isCancelled { status = .failed(error.localizedDescription) }
    }
  }
  static func grouped(_ reply: String) -> String {
    let prefix = "ezcrypt1:"
    guard reply.hasPrefix(prefix) else { return reply }
    var groups = [prefix]
    var rest = reply.dropFirst(prefix.count)
    while !rest.isEmpty {
      groups.append(String(rest.prefix(8)))
      rest = rest.dropFirst(8)
    }
    return groups.joined(separator: " ")
  }
  private func copyInstead() {
    do {
      let text = try Link.replyText(offer, payload)
      PlatformUI.copy(text)
      reply = text
      replyError = nil
      route = .paste
    } catch { replyError = error.localizedDescription }
  }
}
