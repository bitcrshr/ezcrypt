import Foundation
import Observation

/// What a scanned `ezcrypt://link` offer asks for.
enum LinkKind: String, Decodable { case trust, enroll }

/// An offer as shown before the person confirms. `url` is passed back to the
/// core for every later step; Swift never parses it.
struct LinkOffer: Identifiable, Hashable {
  let id: UUID
  let url: String
  let kind: LinkKind
  let host: String
  let user: String
  let subjectPublicKey: String?
  let subjectFingerprint: String?
}

/// The only things that may be sent to a machine. The core normalises and
/// re-checks both before they leave the device.
enum LinkPayload {
  case caKey(publicKey: String, name: String)
  case certificate(String)
  var object: [String: Any] {
    switch self {
    case .caKey(let publicKey, let name):
      ["type": "ca_key", "public_key": publicKey, "name": name]
    case .certificate(let certificate):
      ["type": "certificate", "certificate": certificate]
    }
  }
}

/// The machine's answer: `ok` is false when it refused or failed to apply the payload.
struct LinkOutcome: Decodable {
  let ok: Bool
  let message: String
  private enum CodingKeys: String, CodingKey { case outcome, message }
  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    ok = try container.decode(String.self, forKey: .outcome) == "ok"
    message = try container.decode(String.self, forKey: .message)
  }
}

enum Link {
  static func offer(_ url: String) throws -> LinkOffer {
    struct Info: Decodable {
      enum CodingKeys: String, CodingKey {
        case kind, host, user
        case subjectPublicKey = "subject_public_key"
        case subjectFingerprint = "subject_fingerprint"
      }
      var kind: LinkKind
      var host: String
      var user: String
      var subjectPublicKey: String?
      var subjectFingerprint: String?
    }
    let info: Info = try Core.call(["op": "link_offer", "url": url])
    return LinkOffer(
      id: UUID(), url: url, kind: info.kind, host: info.host, user: info.user,
      subjectPublicKey: info.subjectPublicKey, subjectFingerprint: info.subjectFingerprint)
  }

  /// The reply to paste into the waiting terminal when the network can't connect.
  static func replyText(_ offer: LinkOffer, _ payload: LinkPayload) throws -> String {
    struct Reply: Decodable { var text: String }
    let reply: Reply = try Core.call(
      ["op": "link_reply_text", "url": offer.url, "payload": payload.object])
    return reply.text
  }

  /// Sends the payload to the machine and waits for its answer, which can take
  /// minutes. Cancelling the calling task cancels the delivery and throws
  /// `CancellationError`.
  static func deliver(_ offer: LinkOffer, _ payload: LinkPayload) async throws -> LinkOutcome {
    let input = try JSONSerialization.data(
      withJSONObject: ["offer": offer.url, "payload": payload.object], options: [.sortedKeys])
    guard let raw = ezcrypt_link_new() else { throw AppFailure("Couldn’t start link delivery") }
    let handle = LinkHandle(raw: raw)
    // The cancellation handler can't outlive withTaskCancellationHandler, and the
    // blocking call has returned by the time it does, so freeing here is safe.
    defer { ezcrypt_link_free(handle.raw) }
    let response = await withTaskCancellationHandler {
      await withCheckedContinuation { (continuation: CheckedContinuation<Data?, Never>) in
        // A plain thread, not the cooperative pool: this blocks for up to ~11 minutes.
        Thread.detachNewThread {
          let result = input.withUnsafeBytes { bytes in
            ezcrypt_link_deliver(
              handle.raw, bytes.bindMemory(to: UInt8.self).baseAddress, input.count)
          }
          guard let result else { return continuation.resume(returning: nil) }
          let data = Data(bytes: result, count: strlen(result))
          ezcrypt_free(result)
          continuation.resume(returning: data)
        }
      }
    } onCancel: {
      ezcrypt_link_cancel(handle.raw)
    }
    guard let response,
      let envelope = try JSONSerialization.jsonObject(with: response) as? [String: Any]
    else { throw AppFailure("No response from link delivery") }
    if let error = envelope["error"] as? String {
      if error == "Cancelled" { throw CancellationError() }
      throw AppFailure(error)
    }
    guard let outcome = envelope["ok"] else {
      throw AppFailure("Invalid response from link delivery")
    }
    return try JSONDecoder().decode(
      LinkOutcome.self, from: JSONSerialization.data(withJSONObject: outcome))
  }
}

/// The handle crosses to the delivery thread; the C API makes cancel thread-safe.
private struct LinkHandle: @unchecked Sendable {
  let raw: OpaquePointer
}

enum LinkRoute: Hashable {
  case scan
  case offer(LinkOffer)
}

/// Routes `ezcrypt://` URLs, from a deep link or the scanner, to the link sheet.
@MainActor @Observable
final class LinkRouter {
  var offer: LinkOffer?
  var error: String?
  /// The scanner is showing in the link sheet.
  var scanning = false
  var presenting: Bool { route != nil }
  /// What the link sheet shows: an offer, else the scanner, else nothing.
  var route: LinkRoute? {
    if let offer { .offer(offer) } else if scanning { .scan } else { nil }
  }
  func open(_ url: URL) {
    guard url.scheme?.lowercased() == "ezcrypt" else { return }
    do {
      offer = try Link.offer(url.absoluteString)
      error = nil
    } catch {
      self.error = error.localizedDescription
    }
  }
  /// Opens pasted text, explaining when it isn't a link at all.
  func open(pasted text: String?) {
    let trimmed = text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard let url = URL(string: trimmed), url.scheme?.lowercased() == "ezcrypt" else {
      error = "That isn’t an ezcrypt link. Copy the ezcrypt:// link shown in the terminal."
      return
    }
    open(url)
  }
  func close() {
    offer = nil
    scanning = false
  }
}
