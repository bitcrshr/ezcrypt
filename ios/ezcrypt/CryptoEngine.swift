import Foundation
import LocalAuthentication
import Security

/// Debug Simulator sessions get an isolated, visibly marked test key store.
/// There is no fallback to software hardware-keys on a physical device.
enum RuntimeMode {
  static var demo: Bool {
    #if DEBUG && targetEnvironment(simulator)
      ProcessInfo.processInfo.arguments.contains("--demo")
        || ProcessInfo.processInfo.environment["EZCRYPT_TEST_MODE"] == "1"
    #else
      false
    #endif
  }
}

private final class HardwareContext {
  let key: SecKey
  let authentication: LAContext
  var error: Error?
  init(key: SecKey, authentication: LAContext) {
    self.key = key
    self.authentication = authentication
  }
}

private let hardwareCallback: ezcrypt_hardware_callback = {
  opaque, operation, input, count, output, capacity in
  guard let opaque, let input, let output else { return -1 }
  let context = Unmanaged<HardwareContext>.fromOpaque(opaque).takeUnretainedValue()
  do {
    var failure: Unmanaged<CFError>?
    let result: CFData
    if operation == 1 {
      guard
        let signature = SecKeyCreateSignature(
          context.key, .ecdsaSignatureMessageX962SHA256, Data(bytes: input, count: count) as CFData,
          &failure)
      else {
        throw failure?.takeRetainedValue() as Error? ?? AppFailure("Signing failed")
      }
      result = signature
    } else if operation == 2 {
      let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits as String: 256,
      ]
      guard
        let peer = SecKeyCreateWithData(
          Data(bytes: input, count: count) as CFData, attrs as CFDictionary, &failure)
      else {
        throw failure?.takeRetainedValue() as Error? ?? AppFailure("Invalid wrapping public key")
      }
      guard
        let shared = SecKeyCopyKeyExchangeResult(
          context.key, .ecdhKeyExchangeStandard, peer, [:] as CFDictionary, &failure)
      else {
        throw failure?.takeRetainedValue() as Error? ?? AppFailure("Key agreement failed")
      }
      result = shared
    } else {
      throw AppFailure("Unknown hardware operation")
    }
    let length = CFDataGetLength(result)
    guard length <= capacity else { throw AppFailure("Invalid hardware output length") }
    // Copy directly into Rust's zeroizing output buffer. This is an ECDH
    // result or signature, never a plaintext software CA key.
    output.update(from: CFDataGetBytePtr(result), count: length)
    return Int32(length)
  } catch {
    context.error = error
    return -1
  }
}

enum Core {
  static func call<T: Decodable>(
    _ command: [String: Any], secret: String = "", context: AnyObject? = nil
  ) throws -> T {
    let data = try JSONSerialization.data(withJSONObject: command, options: [.sortedKeys])
    var password = Array(secret.utf8)
    defer {
      password.withUnsafeMutableBytes { bytes in
        if let p = bytes.baseAddress { memset_s(p, bytes.count, 0, bytes.count) }
      }
    }
    let opaque = context.map { Unmanaged.passUnretained($0).toOpaque() }
    let result = data.withUnsafeBytes { bytes in
      password.withUnsafeBufferPointer { secretBytes in
        ezcrypt_call(
          bytes.bindMemory(to: UInt8.self).baseAddress, data.count, secretBytes.baseAddress,
          secretBytes.count, opaque == nil ? nil : hardwareCallback, opaque)
      }
    }
    guard let result else { throw AppFailure("No response from cryptographic core") }
    defer { ezcrypt_free(result) }
    let response = Data(bytes: result, count: strlen(result))
    let envelope = try JSONSerialization.jsonObject(with: response) as? [String: Any]
    if let error = envelope?["error"] as? String {
      if let error = (context as? HardwareContext)?.error { throw error }
      throw AppFailure(error)
    }
    guard let payload = envelope?["ok"] else {
      throw AppFailure("Invalid response from cryptographic core")
    }
    return try JSONDecoder().decode(T.self, from: JSONSerialization.data(withJSONObject: payload))
  }
}

actor CryptoEngine {
  private func tag(_ id: UUID) -> Data {
    Data("app.ezcrypt.\(RuntimeMode.demo ? "demo" : "device").\(id.uuidString)".utf8)
  }
  private func context(_ reason: String) -> LAContext {
    let context = LAContext()
    context.localizedReason = reason
    context.touchIDAuthenticationAllowableReuseDuration = 0
    return context
  }
  func authenticate(_ reason: String) async throws {
    if RuntimeMode.demo { return }
    let auth = context(reason)
    defer { auth.invalidate() }
    guard try await auth.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else {
      throw AppFailure("Authentication required")
    }
  }
  private func createHardware(_ id: UUID) throws -> (SecKey, Data) {
    var error: Unmanaged<CFError>?
    var attrs: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
    ]
    var privateAttrs: [String: Any] = [
      kSecAttrIsPermanent as String: true, kSecAttrApplicationTag as String: tag(id),
    ]
    if RuntimeMode.demo {
      privateAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    } else {
      #if targetEnvironment(simulator)
        throw AppFailure(
          "Secure Enclave requires an iPhone or iPad. Launch a Debug Simulator session with --demo for isolated test keys."
        )
      #else
        guard
          let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .userPresence], &error)
        else {
          throw error?.takeRetainedValue() as Error?
            ?? AppFailure("Cannot create key access policy")
        }
        attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        privateAttrs[kSecAttrAccessControl as String] = access
      #endif
    }
    attrs[kSecPrivateKeyAttrs as String] = privateAttrs
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error),
      let publicKey = SecKeyCopyPublicKey(key),
      let bytes = SecKeyCopyExternalRepresentation(publicKey, &error)
    else {
      throw error?.takeRetainedValue() as Error?
        ?? AppFailure("Unable to create Secure Enclave key")
    }
    return (key, bytes as Data)
  }
  private func load(_ id: UUID, reason: String) throws -> HardwareContext {
    let auth = context(reason)
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag(id),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecReturnRef as String: true,
      kSecUseAuthenticationContext as String: auth,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let result else {
      auth.invalidate()
      throw AppFailure("This device cannot access the CA key (Keychain \(status)).")
    }
    return HardwareContext(key: result as! SecKey, authentication: auth)
  }
  func create(name: String, purpose: Purpose, custody: Custody, algorithm: KeyAlgorithm)
    async throws -> Authority
  {
    try await authenticate("Create \(name) certificate authority")
    let id = UUID()
    do {
      let (_, publicBytes) = try createHardware(id)
      let pub = publicBytes.base64EncodedString()
      struct Created: Decodable {
        enum CodingKeys: String, CodingKey {
          case publicKey = "public_key"
          case fingerprint
        }
        var publicKey: String
        var fingerprint: String
      }
      if custody == .enclave {
        let value: Created = try Core.call(["op": "hardware_public", "public": pub])
        return Authority(
          id: id, name: name, purpose: purpose, custody: custody, algorithm: .p256,
          publicKey: value.publicKey, fingerprint: value.fingerprint, hardwarePublic: pub,
          created: Date())
      }
      // The envelope is opaque to Swift: only ciphertext and public metadata.
      struct EnvelopeResponse: Decodable {
        enum CodingKeys: String, CodingKey {
          case publicKey = "public_key"
          case fingerprint, record
        }
        var publicKey: String
        var fingerprint: String
        var record: JSONValue
      }
      let value: EnvelopeResponse = try Core.call([
        "op": "create_software", "id": id.uuidString, "algorithm": algorithm.rawValue,
        "purpose": purpose.rawValue, "device_public": pub,
      ])
      return Authority(
        id: id, name: name, purpose: purpose, custody: custody, algorithm: algorithm,
        publicKey: value.publicKey, fingerprint: value.fingerprint, hardwarePublic: pub,
        envelope: try JSONEncoder().encode(value.record), created: Date())
    } catch {
      try? removeKey(id)
      throw error
    }
  }
  func prepare(_ request: SigningRequest, authority: Authority) throws -> Prepared {
    try Core.call(["op": "prepare", "request": request.object(), "ca_public": authority.publicKey])
  }
  func issue(_ request: SigningRequest, authority: Authority) throws -> IssuedPayload {
    let context = try load(
      authority.id,
      reason:
        "Sign \(request.keyID.isEmpty ? "SSH certificate" : request.keyID) with \(authority.name)"
    )
    defer { context.authentication.invalidate() }
    if authority.custody == .enclave {
      return try Core.call(
        [
          "op": "issue_hardware", "public": authority.hardwarePublic,
          "purpose": authority.purpose.rawValue, "request": request.object(),
        ], context: context)
    }
    guard let envelope = authority.envelope else { throw AppFailure("Missing encrypted CA key") }
    return try Core.call(
      [
        "op": "issue_software", "record": envelope.object(), "id": authority.id.uuidString,
        "purpose": authority.purpose.rawValue, "request": request.object(),
      ], context: context)
  }
  func recipient(_ armor: String) throws -> Recipient {
    try Core.call(["op": "recipient", "armor": armor])
  }
  func export(
    authority: Authority, password: String, armor: String, fingerprint: String, useGPG: Bool
  ) throws -> Exported {
    guard authority.custody == .software, let envelope = authority.envelope else {
      throw AppFailure("Secure Enclave CA keys cannot be exported")
    }
    let context = try load(authority.id, reason: "Export \(authority.name) private CA key")
    defer { context.authentication.invalidate() }
    return try Core.call(
      [
        "op": "export", "record": envelope.object(), "id": authority.id.uuidString,
        "purpose": authority.purpose.rawValue, "format": useGPG ? "gpg" : "passphrase",
        "armor": armor, "fingerprint": fingerprint,
      ], secret: password, context: context)
  }
  func removeKey(_ id: UUID) throws {
    let status = SecItemDelete(
      [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag(id)] as CFDictionary
    )
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw AppFailure("Cannot remove key (Keychain \(status))")
    }
  }
}

/// Lossless JSON for an opaque Rust envelope; preserves integer bytes exactly.
indirect enum JSONValue: Codable {
  case object([String: JSONValue])
  case array([JSONValue])
  case string(String)
  case integer(UInt64)
  case bool(Bool)
  case null
  init(from decoder: Decoder) throws {
    let c = try decoder.singleValueContainer()
    if c.decodeNil() {
      self = .null
    } else if let b = try? c.decode(Bool.self) {
      self = .bool(b)
    } else if let n = try? c.decode(UInt64.self) {
      self = .integer(n)
    } else if let s = try? c.decode(String.self) {
      self = .string(s)
    } else if let a = try? c.decode([JSONValue].self) {
      self = .array(a)
    } else {
      self = .object(try c.decode([String: JSONValue].self))
    }
  }
  func encode(to encoder: Encoder) throws {
    var c = encoder.singleValueContainer()
    switch self {
    case .object(let v): try c.encode(v)
    case .array(let v): try c.encode(v)
    case .string(let v): try c.encode(v)
    case .integer(let v): try c.encode(v)
    case .bool(let v): try c.encode(v)
    case .null: try c.encodeNil()
    }
  }
}
