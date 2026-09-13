import XCTest

@testable import ezcrypt

final class EzcryptTests: XCTestCase {
  override func setUp() { setenv("EZCRYPT_TEST_MODE", "1", 1) }
  private func request(_ publicKey: String, purpose: Purpose = .user, serial: String = "1")
    -> SigningRequest
  {
    SigningRequest(
      publicKey: publicKey, purpose: purpose, keyID: "test", serial: serial,
      principals: ["alice"], allPrincipals: false, validAfter: 1, validBefore: nil,
      criticalOptions: [:], extensions: purpose == .user ? ["permit-pty": ""] : [:])
  }
  func testAppleECDHBridgeForAllSoftwareAlgorithms() async throws {
    let engine = CryptoEngine()
    for algorithm in KeyAlgorithm.allCases {
      let ca = try await engine.create(
        name: "Test", purpose: .user, custody: .software, algorithm: algorithm)
      let prepared = try await engine.prepare(request(ca.publicKey), authority: ca)
      let issued = try await engine.issue(prepared.request, authority: ca)
      XCTAssertNil(issued.request.validBefore)
      XCTAssertEqual(issued.caFingerprint, ca.fingerprint)
      XCTAssertTrue(issued.certificate.contains("-cert-v01@openssh.com"))
      let exported = try await engine.export(
        authority: ca, password: "public test password", armor: "", fingerprint: "", useGPG: false)
      XCTAssertTrue(
        String(data: Data(base64Encoded: exported.data)!, encoding: .utf8)!.contains(
          "BEGIN OPENSSH PRIVATE KEY"))
      try await engine.removeKey(ca.id)
    }
  }
  func testHardwareSigningCallback() async throws {
    let engine = CryptoEngine()
    let ca = try await engine.create(
      name: "Hardware path", purpose: .host, custody: .enclave, algorithm: .p256)
    let issued = try await engine.issue(request(ca.publicKey, purpose: .host), authority: ca)
    XCTAssertEqual(issued.caFingerprint, ca.fingerprint)
    do {
      _ = try await engine.issue(request(ca.publicKey, purpose: .user), authority: ca)
      XCTFail("Purpose mismatch accepted")
    } catch {}
    try await engine.removeKey(ca.id)
    do {
      _ = try await engine.issue(request(ca.publicKey, purpose: .host), authority: ca)
      XCTFail("Deleted key used")
    } catch {}
  }
  @MainActor func testPersistenceDuplicatesAndSerialReservation() async throws {
    let file = URL.temporaryDirectory.appending(path: UUID().uuidString).appending(
      path: "inventory.json")
    let store = InventoryStore(file: file)
    try await store.create(name: "Work", purpose: .user, custody: .software, algorithm: .ed25519)
    let ca = try XCTUnwrap(store.authorities.first)
    let prepared = try await store.prepare(request(ca.publicKey), authority: ca)
    let issued = try await store.issue(prepared, authorityID: ca.id, allowDuplicate: false)
    XCTAssertEqual(issued.payload.request.serial, "1")
    let reopened = InventoryStore(file: file)
    XCTAssertEqual(reopened.certificates.count, 1)
    XCTAssertEqual(reopened.authorities.first?.nextSerial, 2)
    let duplicate = try await reopened.prepare(request(ca.publicKey, serial: "2"), authority: ca)
    XCTAssertEqual(reopened.duplicates(duplicate).count, 1)
    do {
      _ = try await reopened.issue(duplicate, authorityID: ca.id, allowDuplicate: false)
      XCTFail("Duplicate accepted without override")
    } catch {}
    _ = try await reopened.issue(duplicate, authorityID: ca.id, allowDuplicate: true)
    XCTAssertEqual(reopened.certificates.count, 2)
    try await reopened.remove(ca)
    XCTAssertEqual(reopened.authorities.count, 0)
    XCTAssertEqual(reopened.certificates.count, 2)
  }
  @MainActor func testMissingKeyConsumesSerialWithoutIssuing() async throws {
    let file = URL.temporaryDirectory.appending(path: UUID().uuidString).appending(
      path: "inventory.json")
    let store = InventoryStore(file: file)
    try await store.create(
      name: "Unavailable", purpose: .user, custody: .software, algorithm: .p256)
    let ca = try XCTUnwrap(store.authorities.first)
    let prepared = try await store.prepare(request(ca.publicKey), authority: ca)
    try await store.engine.removeKey(ca.id)
    do {
      _ = try await store.issue(prepared, authorityID: ca.id, allowDuplicate: false)
      XCTFail("Missing hardware key signed")
    } catch {}
    let reopened = InventoryStore(file: file)
    XCTAssertEqual(reopened.authorities.first?.nextSerial, 2)
    XCTAssertTrue(reopened.certificates.isEmpty)
    XCTAssertNil(reopened.pendingCertificate)
  }

  @MainActor func testCorruptInventoryDoesNotBecomeEmptyWritableStore() throws {
    let file = URL.temporaryDirectory.appending(path: UUID().uuidString)
    try Data("corrupt".utf8).write(to: file)
    let store = InventoryStore(file: file)
    XCTAssertNotNil(store.loadFailure)
    XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), "corrupt")
  }
  func testValidityBoundariesAndForeverDecoding() throws {
    let payload = IssuedPayload(
      certificate: "test", subjectFingerprint: "subject", caFingerprint: "ca", duplicateID: "id",
      request: request("public"))
    var certificate = CertificateRecord(
      id: UUID(), authorityID: UUID(), authorityName: "Work", issuedAt: Date(), payload: payload)
    certificate.payload.request.validAfter = 100
    certificate.payload.request.validBefore = 200
    XCTAssertEqual(certificate.status(at: Date(timeIntervalSince1970: 99)), .scheduled)
    XCTAssertEqual(certificate.status(at: Date(timeIntervalSince1970: 100)), .valid)
    XCTAssertEqual(certificate.status(at: Date(timeIntervalSince1970: 200)), .expired)
    certificate.payload.request.validBefore = nil
    let restored = try JSONDecoder().decode(
      CertificateRecord.self, from: JSONEncoder().encode(certificate))
    XCTAssertNil(restored.payload.request.validBefore)
    XCTAssertEqual(restored.status(at: Date(timeIntervalSince1970: 10_000_000_000)), .valid)
  }
}
