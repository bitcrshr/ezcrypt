import XCTest

@testable import ezcrypt

final class InventoryLifecycleTests: XCTestCase {
  private func fixture() -> Inventory {
    let authority = Authority(
      id: UUID(), name: "Lifecycle fixture", purpose: .user,
      custody: .software, algorithm: .ed25519, publicKey: "public", fingerprint: "fingerprint",
      hardwarePublic: "wrapping-public", envelope: Data([1, 2, 3]), created: Date(), nextSerial: 42)
    let request = SigningRequest(
      publicKey: "subject", purpose: .user, keyID: "fixture", serial: "41",
      principals: ["alice"], allPrincipals: false, validAfter: 1, validBefore: nil,
      criticalOptions: [:], extensions: [:])
    let certificate = CertificateRecord(
      id: UUID(), authorityID: authority.id,
      authorityName: authority.name, issuedAt: Date(),
      payload: IssuedPayload(
        certificate: "public-certificate", subjectFingerprint: "subject",
        caFingerprint: "fingerprint",
        duplicateID: "duplicate", request: request))
    return Inventory(authorities: [authority], certificates: [certificate])
  }
  private func write(_ inventory: Inventory) throws -> URL {
    let directory = URL.temporaryDirectory.appending(path: UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let file = directory.appending(path: "inventory.json")
    try JSONEncoder().encode(inventory).write(to: file)
    return file
  }
  @MainActor func testAuthorityArchiveRoundTripPreservesCustodyAndSerial() async throws {
    let initial = fixture()
    let file = try write(initial)
    defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
    let store = InventoryStore(file: file)
    let ca = initial.authorities[0]
    try store.setAuthorityArchived(ca.id, archived: true)
    XCTAssertTrue(store.authorities.isEmpty)
    XCTAssertEqual(store.visibleAuthorities(.archived).map(\.id), [ca.id])
    let reopened = InventoryStore(file: file)
    XCTAssertEqual(reopened.authority(ca.id)?.envelope, ca.envelope)
    XCTAssertEqual(reopened.authority(ca.id)?.nextSerial, 42)
    XCTAssertEqual(reopened.authority(ca.id)?.archived, false)
    var request = initial.certificates[0].payload.request
    request.serial = "42"
    let prepared = Prepared(request: request, duplicateID: "new", subjectFingerprint: "subject")
    do {
      _ = try await reopened.issue(prepared, authorityID: ca.id, allowDuplicate: true)
      XCTFail("Archived CA accepted for signing")
    } catch {
      XCTAssertEqual(error.localizedDescription, "This CA is no longer available.")
    }
    XCTAssertEqual(reopened.authority(ca.id)?.nextSerial, 42)
    try reopened.setAuthorityArchived(ca.id, archived: false)
    XCTAssertEqual(reopened.authorities.map(\.id), [ca.id])
    XCTAssertEqual(reopened.authority(ca.id)?.envelope, ca.envelope)
  }
  @MainActor func testCertificateArchiveRetainsDuplicatesAndDeletePreservesSerial() throws {
    let initial = fixture()
    let file = try write(initial)
    defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
    let record = initial.certificates[0]
    let store = InventoryStore(file: file)
    let prepared = Prepared(
      request: record.payload.request, duplicateID: record.payload.duplicateID,
      subjectFingerprint: record.payload.subjectFingerprint)
    try store.setCertificateArchived(record.id, archived: true)
    let reopened = InventoryStore(file: file)
    XCTAssertTrue(try XCTUnwrap(reopened.certificates.first).isArchived)
    XCTAssertEqual(reopened.duplicates(prepared).map(\.id), [record.id])
    try reopened.setCertificateArchived(record.id, archived: false)
    XCTAssertFalse(try XCTUnwrap(reopened.certificates.first).isArchived)
    try reopened.deleteCertificate(record.id)
    let deleted = InventoryStore(file: file)
    XCTAssertTrue(deleted.certificates.isEmpty)
    XCTAssertTrue(deleted.duplicates(prepared).isEmpty)
    XCTAssertEqual(deleted.authority(record.authorityID)?.nextSerial, 42)
    XCTAssertEqual(deleted.authority(record.authorityID)?.envelope, initial.authorities[0].envelope)
  }
  @MainActor func testLegacyRemovedAuthorityCannotBeRestored() throws {
    var initial = fixture()
    initial.authorities[0].archived = true
    initial.authorities[0].envelope = nil
    let file = try write(initial)
    defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
    // Optional archive fields are absent in a pre-feature inventory.
    let json = try String(contentsOf: file, encoding: .utf8)
    XCTAssertFalse(json.contains("inventoryArchived"))
    let store = InventoryStore(file: file)
    XCTAssertFalse(store.certificates[0].isArchived)
    XCTAssertTrue(store.authorities.isEmpty)
    XCTAssertEqual(store.visibleAuthorities(.archived).count, 1)
    XCTAssertThrowsError(try store.setAuthorityArchived(initial.authorities[0].id, archived: false))
    XCTAssertTrue(try XCTUnwrap(store.authority(initial.authorities[0].id)).archived)
  }
  @MainActor func testFailedArchiveOrDeleteDoesNotChangeMemoryOrDisk() throws {
    let initial = fixture()
    let file = try write(initial)
    defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
    let before = try Data(contentsOf: file)
    let store = InventoryStore(file: file) { _, _ in throw AppFailure("Disk unavailable") }
    XCTAssertThrowsError(try store.setAuthorityArchived(initial.authorities[0].id, archived: true))
    XCTAssertThrowsError(
      try store.setCertificateArchived(initial.certificates[0].id, archived: true))
    XCTAssertThrowsError(try store.deleteCertificate(initial.certificates[0].id))
    XCTAssertEqual(store.authorities.count, 1)
    XCTAssertFalse(store.certificates[0].isArchived)
    XCTAssertEqual(try Data(contentsOf: file), before)
    XCTAssertFalse(store.busy)
  }
}
