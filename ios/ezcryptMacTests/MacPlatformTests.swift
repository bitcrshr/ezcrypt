import XCTest

@testable import ezcrypt

/// Native Mac checks deliberately avoid creating keys or presenting authentication.
final class MacPlatformTests: XCTestCase {
  func testMacCannotEnableSimulatorKeyBackend() {
    let previous = ProcessInfo.processInfo.environment["EZCRYPT_TEST_MODE"]
    setenv("EZCRYPT_TEST_MODE", "1", 1)
    defer {
      if let previous {
        setenv("EZCRYPT_TEST_MODE", previous, 1)
      } else {
        unsetenv("EZCRYPT_TEST_MODE")
      }
    }
    XCTAssertFalse(RuntimeMode.demo)
  }

  @MainActor func testNativeInventoryReloadAndCorruptionHandling() throws {
    let directory = URL.temporaryDirectory.appending(path: UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let file = directory.appending(path: "inventory.json")
    let authority = Authority(
      id: UUID(), name: "Public inventory fixture", purpose: .user,
      custody: .enclave, algorithm: .p256, publicKey: "fixture", fingerprint: "fixture",
      hardwarePublic: "fixture", created: Date())
    try JSONEncoder().encode(Inventory(authorities: [authority])).write(to: file)
    let store = InventoryStore(file: file)
    XCTAssertNil(store.loadFailure)
    XCTAssertEqual(store.authorities.map(\.id), [authority.id])
    try Data("broken".utf8).write(to: file)
    store.reload()
    XCTAssertNotNil(store.loadFailure)
    XCTAssertEqual(store.authorities.map(\.id), [authority.id])
    XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), "broken")
  }

  func testNativeFilesystemSupportsInventoryProtectionOptions() throws {
    let directory = URL.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: true,
      attributes: [.protectionKey: FileProtectionType.complete])
    var excluded = directory
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try excluded.setResourceValues(values)
    let file = directory.appending(path: "inventory.json")
    try Data("{}".utf8).write(to: file, options: [.atomic, .completeFileProtection])
    XCTAssertEqual(try Data(contentsOf: file), Data("{}".utf8))
    XCTAssertEqual(
      try excluded.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
  }

  @MainActor func testCertificateFilePreservesOpenSSHBytes() throws {
    let request = SigningRequest(
      publicKey: "fixture", purpose: .user, keyID: "test",
      serial: "18446744073709551615", principals: ["alice"], allPrincipals: false,
      validAfter: 1, validBefore: nil, criticalOptions: [:], extensions: [:])
    let record = CertificateRecord(
      id: UUID(), authorityID: UUID(), authorityName: "Fixture",
      issuedAt: Date(),
      payload: IssuedPayload(
        certificate: "ssh-ed25519-cert-v01@openssh.com fixture",
        subjectFingerprint: "subject", caFingerprint: "ca", duplicateID: "duplicate",
        request: request))
    let store = InventoryStore(file: URL.temporaryDirectory.appending(path: UUID().uuidString))
    let file = try store.certificateFile(record)
    defer { try? FileManager.default.removeItem(at: file) }
    XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), record.payload.certificate + "\n")
    XCTAssertTrue(file.lastPathComponent.hasSuffix("-cert.pub"))
    let decoded = try JSONDecoder().decode(
      CertificateRecord.self, from: JSONEncoder().encode(record))
    XCTAssertEqual(decoded.payload.request.serial, "18446744073709551615")
    XCTAssertNil(decoded.payload.request.validBefore)
  }
}
