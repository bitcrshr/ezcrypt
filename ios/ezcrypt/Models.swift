import Foundation

enum Purpose: String, Codable, CaseIterable, Identifiable {
  case user, host
  var id: String { rawValue }
  var title: String { self == .user ? "User" : "Host" }
  var symbol: String { self == .user ? "person.crop.square" : "server.rack" }
}
enum Custody: String, Codable, CaseIterable, Identifiable {
  case enclave, software
  var id: String { rawValue }
  var title: String { self == .enclave ? "Secure Enclave" : "Protected software" }
}
enum KeyAlgorithm: String, Codable, CaseIterable, Identifiable {
  case ed25519, p256, p384, p521
  var id: String { rawValue }
  var title: String {
    switch self {
    case .ed25519: "Ed25519"
    case .p256: "P-256"
    case .p384: "P-384"
    case .p521: "P-521"
    }
  }
}
struct Authority: Codable, Identifiable, Hashable {
  var id: UUID
  var name: String
  var purpose: Purpose
  var custody: Custody
  var algorithm: KeyAlgorithm
  var publicKey: String
  var fingerprint: String
  var hardwarePublic: String
  var envelope: Data?
  var created: Date
  var nextSerial: UInt64 = 1
  var exhausted: Bool = false
  var archived: Bool = false
  var keyRemovalPending: Bool?
}
struct SigningRequest: Codable, Hashable {
  enum CodingKeys: String, CodingKey {
    case publicKey = "public_key"
    case keyID = "key_id"
    case allPrincipals = "all_principals"
    case validAfter = "valid_after"
    case validBefore = "valid_before"
    case criticalOptions = "critical_options"
    case purpose, serial, principals, extensions
  }
  var publicKey: String
  var purpose: Purpose
  var keyID: String
  var serial: String
  var principals: [String]
  var allPrincipals: Bool
  var validAfter: UInt64
  var validBefore: UInt64?
  var criticalOptions: [String: String]
  var extensions: [String: String]
}
struct IssuedPayload: Codable, Hashable {
  enum CodingKeys: String, CodingKey {
    case certificate, request
    case subjectFingerprint = "subject_fingerprint"
    case caFingerprint = "ca_fingerprint"
    case duplicateID = "duplicate_id"
  }
  var certificate: String
  var subjectFingerprint: String
  var caFingerprint: String
  var duplicateID: String
  var request: SigningRequest
}
struct CertificateRecord: Codable, Identifiable, Hashable {
  var id: UUID
  var authorityID: UUID
  var authorityName: String
  var issuedAt: Date
  var payload: IssuedPayload
  var title: String {
    payload.request.keyID.isEmpty
      ? payload.request.principals.joined(separator: ", ") : payload.request.keyID
  }
  var status: CertificateStatus { status(at: Date()) }
  func status(at date: Date) -> CertificateStatus {
    let now = UInt64(max(0, date.timeIntervalSince1970))
    if now < payload.request.validAfter { return .scheduled }
    if let end = payload.request.validBefore, now >= end { return .expired }
    return .valid
  }
  var searchable: String {
    [
      title, authorityName, payload.subjectFingerprint, payload.caFingerprint,
      payload.request.serial, payload.request.principals.joined(separator: " "),
    ].joined(separator: " ")
  }
}
enum CertificateStatus: String, CaseIterable {
  case valid = "Valid"
  case scheduled = "Scheduled"
  case expired = "Expired"
}
struct Inventory: Codable {
  var version = 1
  var authorities: [Authority] = []
  var certificates: [CertificateRecord] = []
}
struct Prepared: Decodable {
  enum CodingKeys: String, CodingKey {
    case request
    case duplicateID = "duplicate_id"
    case subjectFingerprint = "subject_fingerprint"
  }
  var request: SigningRequest
  var duplicateID: String
  var subjectFingerprint: String
}
struct Recipient: Decodable {
  var fingerprint: String
  var subkey: String
}
struct Exported: Decodable {
  var data: String
  var `extension`: String
}
struct AppFailure: LocalizedError {
  var message: String
  init(_ message: String) { self.message = message }
  var errorDescription: String? { message }
}
extension Data {
  func object() throws -> Any { try JSONSerialization.jsonObject(with: self) }
}
extension Encodable {
  func object() throws -> Any { try JSONEncoder().encode(self).object() }
}
