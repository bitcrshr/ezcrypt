import XCTest

@testable import ezcrypt

/// Offers built from fixed, valid keys: an Ed25519 endpoint nobody listens on,
/// a 16-byte secret, and (for enroll) an Ed25519 subject key.
enum LinkFixture {
  static let endpoint = "DXkjIG5OQjn-78xvw45oUCR_EsLgqNtPTCfd9TqVXr4"
  static let secret = "AAECAwQFBgcICQoLDA0ODw"
  static let trustURL = "ezcrypt://link?v=1&k=trust&n=\(endpoint)&s=\(secret)&h=testhost&u=alice"
  static let subject = "AAAAC3NzaC1lZDI1NTE5AAAAINNcLAdH671SK8nIRzpXm7jyeWx96Lad-lAQsTnMQNfA"
  static let enrollURL =
    "ezcrypt://link?v=1&k=enroll&n=\(endpoint)&s=\(secret)&h=build.example.com&u=bob&p=\(subject)"
  static let subjectPublicKey =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINNcLAdH671SK8nIRzpXm7jyeWx96Lad+lAQsTnMQNfA"
  static let subjectFingerprint = "SHA256:d0baFV0qYK0F7/XEs5W675EIwlMy74jWXFtqEmdjGH0"
}

final class LinkTests: XCTestCase {
  func testOfferParsesTrustAndEnroll() throws {
    let trust = try Link.offer(LinkFixture.trustURL)
    XCTAssertEqual(trust.kind, .trust)
    XCTAssertEqual(trust.host, "testhost")
    XCTAssertEqual(trust.user, "alice")
    XCTAssertEqual(trust.url, LinkFixture.trustURL)
    XCTAssertNil(trust.subjectPublicKey)
    XCTAssertNil(trust.subjectFingerprint)

    let enroll = try Link.offer(LinkFixture.enrollURL)
    XCTAssertEqual(enroll.kind, .enroll)
    XCTAssertEqual(enroll.host, "build.example.com")
    XCTAssertEqual(enroll.user, "bob")
    XCTAssertEqual(enroll.subjectPublicKey, LinkFixture.subjectPublicKey)
    XCTAssertEqual(enroll.subjectFingerprint, LinkFixture.subjectFingerprint)
    XCTAssertNotEqual(trust.id, try Link.offer(LinkFixture.trustURL).id)
  }

  func testOfferRejectsGarbage() {
    XCTAssertThrowsError(try Link.offer("https://example.com/link?v=1"))
    XCTAssertThrowsError(
      try Link.offer(LinkFixture.trustURL.replacingOccurrences(of: "v=1", with: "v=9"))
    ) {
      XCTAssertEqual($0.localizedDescription, "This QR code needs a newer ezcrypt app")
    }
  }

  func testReplyTextCarriesCAKey() throws {
    let offer = try Link.offer(LinkFixture.trustURL)
    let text = try Link.replyText(
      offer, .caKey(publicKey: LinkFixture.subjectPublicKey, name: "Home CA"))
    XCTAssertTrue(text.hasPrefix("ezcrypt1:"), text)
    // A certificate is the wrong payload for a trust offer.
    XCTAssertThrowsError(
      try Link.replyText(offer, .certificate("ssh-ed25519-cert-v01@openssh.com AAAA")))
  }

  func testCancelledDeliveryThrowsCancellationError() async throws {
    let offer = try Link.offer(LinkFixture.trustURL)
    let delivery = Task {
      try await Link.deliver(
        offer, .caKey(publicKey: LinkFixture.subjectPublicKey, name: "Home CA"))
    }
    delivery.cancel()
    do {
      _ = try await delivery.value
      XCTFail("Cancelled delivery returned an outcome")
    } catch {
      XCTAssertTrue(error is CancellationError, "\(error)")
    }
  }

  @MainActor func testRouterPrefersOfferOverScannerAndClosesBoth() throws {
    let router = LinkRouter()
    XCTAssertNil(router.route)
    router.scanning = true
    XCTAssertEqual(router.route, .scan)
    router.open(try XCTUnwrap(URL(string: LinkFixture.trustURL)))
    let offer = try XCTUnwrap(router.offer)
    XCTAssertEqual(router.route, .offer(offer))
    router.open(try XCTUnwrap(URL(string: "https://example.com")))
    XCTAssertEqual(router.route, .offer(offer))
    XCTAssertNil(router.error)
    router.open(pasted: "not a link")
    XCTAssertNotNil(router.error)
    router.close()
    XCTAssertNil(router.route)
    XCTAssertFalse(router.presenting)
  }

  @MainActor func testLinkAuthoritiesExcludeHostAndArchived() throws {
    func authority(_ name: String, _ purpose: Purpose) -> Authority {
      Authority(
        id: UUID(), name: name, purpose: purpose, custody: .software, algorithm: .ed25519,
        publicKey: "public", fingerprint: "fingerprint", hardwarePublic: "wrapping",
        created: Date())
    }
    let active = authority("Active user", .user)
    let second = authority("Another user", .user)
    var archived = authority("Archived user", .user)
    archived.inventoryArchived = true
    var removed = authority("Removed user", .user)
    removed.archived = true
    var pending = authority("Pending removal", .user)
    pending.archived = true
    pending.keyRemovalPending = true
    let host = authority("Host", .host)
    let directory = URL.temporaryDirectory.appending(path: UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let file = directory.appending(path: "inventory.json")
    try JSONEncoder().encode(
      Inventory(authorities: [host, second, removed, archived, pending, active])
    ).write(to: file)
    let store = InventoryStore(file: file)
    XCTAssertEqual(store.linkAuthorities(.trust).map(\.id), [active.id, second.id])
    XCTAssertEqual(store.linkAuthorities(.enroll).map(\.id), [active.id, second.id])
  }
}
