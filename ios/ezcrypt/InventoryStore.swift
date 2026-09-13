import Foundation
import Observation

@MainActor @Observable
final class InventoryStore {
  private(set) var inventory = Inventory()
  private(set) var busy = false
  var failure: String?
  private(set) var loadFailure: String?
  let engine = CryptoEngine()
  let file: URL
  private(set) var pendingCertificate: CertificateRecord?
  private(set) var now = Date()
  private let writeInventory: (Data, URL) throws -> Void

  init(
    file: URL? = nil,
    writeInventory: @escaping (Data, URL) throws -> Void = {
      try $0.write(to: $1, options: [.atomic, .completeFileProtection])
    }
  ) {
    self.writeInventory = writeInventory
    self.file =
      file
      ?? URL.applicationSupportDirectory.appending(
        path: RuntimeMode.demo ? "ezcrypt-demo/inventory.json" : "ezcrypt/inventory.json")
    load(allowMissing: true)
  }
  func updateClock(_ date: Date = Date()) { now = date }
  func reload() {
    guard !busy, pendingCertificate == nil else { return }
    load(allowMissing: false)
  }
  private func load(allowMissing: Bool) {
    do {
      let loaded = try JSONDecoder().decode(Inventory.self, from: Data(contentsOf: file))
      guard loaded.version == 1 else {
        throw AppFailure("This inventory was written by a newer version of ezcrypt.")
      }
      guard Set(loaded.authorities.map(\.id)).count == loaded.authorities.count,
        Set(loaded.certificates.map(\.id)).count == loaded.certificates.count
      else { throw AppFailure("Inventory contains duplicate identifiers.") }
      inventory = loaded
      loadFailure = nil
    } catch let error as CocoaError where allowMissing && error.code == .fileReadNoSuchFile {
      // Only first launch may create an empty store. A failed reload must never
      // replace an existing inventory with an empty writable one.
    } catch { loadFailure = error.localizedDescription }
  }
  var authorities: [Authority] {
    inventory.authorities.filter { !$0.archived || $0.keyRemovalPending == true }.sorted {
      $0.name.localizedStandardCompare($1.name) == .orderedAscending
    }
  }
  var certificates: [CertificateRecord] {
    inventory.certificates.sorted { $0.issuedAt > $1.issuedAt }
  }
  func authority(_ id: UUID) -> Authority? { inventory.authorities.first { $0.id == id } }
  private func persist(_ next: Inventory) throws {
    guard loadFailure == nil else {
      throw AppFailure("Resolve the inventory read error before making changes.")
    }
    let directory = file.deletingLastPathComponent()
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: true,
      attributes: [.protectionKey: FileProtectionType.complete])
    var excluded = directory
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try excluded.setResourceValues(values)  // device-bound vaults require explicit portable exports
    let data = try JSONEncoder().encode(next)
    try writeInventory(data, file)
    inventory = next
  }
  private func begin() throws {
    guard !busy, loadFailure == nil, pendingCertificate == nil else {
      throw AppFailure("Finish the current operation before continuing.")
    }
    busy = true
  }
  func create(name: String, purpose: Purpose, custody: Custody, algorithm: KeyAlgorithm)
    async throws
  {
    try begin()
    defer { busy = false }
    let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !name.isEmpty, name.count <= 100 else {
      throw AppFailure("Enter a CA name of 1–100 characters.")
    }
    let authority = try await engine.create(
      name: name, purpose: purpose, custody: custody, algorithm: algorithm)
    do {
      var next = inventory
      next.authorities.append(authority)
      try persist(next)
    } catch {
      try? await engine.removeKey(authority.id)
      throw error
    }
  }
  func prepare(_ request: SigningRequest, authority: Authority) async throws -> Prepared {
    try await engine.prepare(request, authority: authority)
  }
  func duplicates(_ prepared: Prepared, now: Date = Date()) -> [CertificateRecord] {
    certificates.filter { certificate in
      guard certificate.payload.duplicateID == prepared.duplicateID else { return false }
      let old = certificate.payload.request
      let new = prepared.request
      return certificate.status(at: now) == .valid
        || (old.validAfter < (new.validBefore ?? .max)
          && new.validAfter < (old.validBefore ?? .max))
    }
  }
  func issue(_ prepared: Prepared, authorityID: UUID, allowDuplicate: Bool) async throws
    -> CertificateRecord
  {
    try begin()
    defer { busy = false }
    guard var authority = authority(authorityID), !authority.archived else {
      throw AppFailure("This CA is no longer available.")
    }
    guard !authority.exhausted, let serial = UInt64(prepared.request.serial),
      serial >= authority.nextSerial
    else {
      throw AppFailure("Serial has already been used or reserved. Use the next available serial.")
    }
    if !allowDuplicate && !duplicates(prepared).isEmpty {
      throw AppFailure("A matching certificate is still valid or overlaps this interval.")
    }
    // Reserve before signing. Failed/cancelled attempts consume a serial.
    // This makes retry behavior unambiguous across crashes and restarts.
    authority.exhausted = serial == UInt64.max
    authority.nextSerial = serial == UInt64.max ? serial : serial + 1
    var next = inventory
    guard let index = next.authorities.firstIndex(where: { $0.id == authority.id }) else {
      throw AppFailure("CA missing")
    }
    next.authorities[index] = authority
    try persist(next)
    let payload = try await engine.issue(prepared.request, authority: authority)
    let record = CertificateRecord(
      id: UUID(), authorityID: authority.id, authorityName: authority.name, issuedAt: Date(),
      payload: payload)
    pendingCertificate = record
    try savePendingCertificate()
    return record
  }
  @discardableResult func savePendingCertificate() throws -> CertificateRecord? {
    guard let record = pendingCertificate else { return nil }
    var next = inventory
    if !next.certificates.contains(where: { $0.id == record.id }) {
      next.certificates.append(record)
    }
    try persist(next)
    pendingCertificate = nil
    return record
  }
  func export(
    authority: Authority, password: String, armor: String, fingerprint: String, useGPG: Bool
  ) async throws -> URL {
    try begin()
    defer { busy = false }
    guard let current = self.authority(authority.id), !current.archived else {
      throw AppFailure("CA is unavailable")
    }
    let result = try await engine.export(
      authority: current, password: password, armor: armor, fingerprint: fingerprint, useGPG: useGPG
    )
    guard let data = Data(base64Encoded: result.data) else {
      throw AppFailure("Invalid encrypted export")
    }
    return try shareFile(data, name: "ezcrypt-\(authority.id.uuidString).\(result.extension)")
  }
  func remove(_ authority: Authority) async throws {
    try begin()
    defer { busy = false }
    try await engine.authenticate("Permanently remove \(authority.name) private CA key")
    var next = inventory
    guard let index = next.authorities.firstIndex(where: { $0.id == authority.id }) else { return }
    next.authorities[index].archived = true
    next.authorities[index].keyRemovalPending = true
    next.authorities[index].envelope = nil
    // Persist removal intent before touching Keychain, so interrupted removal
    // is visible and retryable after a relaunch.
    try persist(next)
    try await engine.removeKey(authority.id)
    next.authorities[index].keyRemovalPending = false
    try persist(next)
  }
  func shareFile(_ data: Data, name: String) throws -> URL {
    let directory = URL.temporaryDirectory.appending(path: "ezcrypt-exports")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let url = directory.appending(path: name)
    try data.write(to: url, options: [.atomic, .completeFileProtection])
    return url
  }
  func certificateFile(_ certificate: CertificateRecord) throws -> URL {
    try shareFile(
      Data((certificate.payload.certificate + "\n").utf8),
      name: "\(certificate.id.uuidString)-cert.pub")
  }
}
