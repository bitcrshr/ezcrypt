import XCTest

final class EzcryptUITests: XCTestCase {
  @MainActor func testCreateSignInspectDuplicateExportAndRelaunch() throws {
    let app = XCUIApplication()
    app.launchArguments = ["--demo"]
    app.launch()
    XCTAssertTrue(app.staticTexts["demo-banner"].waitForExistence(timeout: 10))
    capture(app, name: "Authorities")
    let name = "Lab \(UUID().uuidString.prefix(6))"
    app.buttons["add-ca"].tap()
    let nameField = app.textFields["ca-name"]
    XCTAssertTrue(nameField.waitForExistence(timeout: 5))
    nameField.tap()
    nameField.typeText(name + "\n")
    reveal(app.buttons["custody-software"], in: app, above: app.buttons["confirm-create-ca"])
    app.buttons["custody-software"].tap()
    capture(app, name: "New authority")
    reveal(app.buttons["confirm-create-ca"], in: app)
    app.buttons["confirm-create-ca"].tap()
    XCTAssertTrue(nameField.waitForNonExistence(timeout: 15))
    try XCTUnwrap(row(name, in: app)).tap()
    XCTAssertTrue(app.buttons["sign-key"].waitForExistence(timeout: 5))
    capture(app, name: "Authority")
    app.buttons["sign-key"].tap()
    let publicKey =
      "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIFhmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmAAAAEHNzaDplemNyeXB0LXRlc3Q="
    fillSigning(app, publicKey: publicKey, capturing: true)
    app.buttons["confirm-sign"].tap()
    XCTAssertTrue(app.buttons["share-certificate"].waitForExistence(timeout: 15))
    capture(app, name: "Issued certificate")
    app.buttons["Done"].tap()
    app.buttons["sign-key"].tap()
    fillSigning(app, publicKey: publicKey)
    XCTAssertTrue(app.staticTexts["Matching certificate already issued"].exists)
    XCTAssertFalse(app.buttons["confirm-sign"].isEnabled)
    capture(app, name: "Duplicate warning")
    app.buttons["Cancel"].tap()
    reveal(app.buttons["export-ca"], in: app)
    app.buttons["export-ca"].tap()
    let password = app.secureTextFields["export-password"]
    XCTAssertTrue(password.waitForExistence(timeout: 5))
    password.tap()
    password.typeText("public test password")
    let confirmation = app.secureTextFields["export-confirmation"]
    confirmation.tap()
    confirmation.typeText("public test password")
    reveal(app.buttons["confirm-export"], in: app)
    app.buttons["confirm-export"].tap()
    XCTAssertTrue(app.buttons["share-backup"].waitForExistence(timeout: 30))
    capture(app, name: "Portable backup")
    app.buttons["Done"].tap()
    app.terminate()
    app.launch()
    XCTAssertTrue(app.buttons["add-ca"].waitForExistence(timeout: 10))
    XCTAssertNotNil(row(name, in: app))
    app.tabBars.buttons["Certificates"].tap()
    XCTAssertTrue(app.staticTexts["workstation"].firstMatch.waitForExistence(timeout: 5))
    capture(app, name: "Certificates")
  }
  @MainActor func testArchiveRestoreAndDeleteInventory() throws {
    let app = XCUIApplication()
    app.launchArguments = ["--demo"]
    app.launch()
    XCTAssertTrue(app.buttons["add-ca"].waitForExistence(timeout: 10))
    let name = "Archive \(UUID().uuidString.prefix(6))"
    app.buttons["add-ca"].tap()
    let nameField = app.textFields["ca-name"]
    XCTAssertTrue(nameField.waitForExistence(timeout: 5))
    nameField.tap()
    nameField.typeText(name + "\n")
    app.buttons["confirm-create-ca"].tap()
    XCTAssertTrue(nameField.waitForNonExistence(timeout: 15))
    try XCTUnwrap(row(name, in: app)).tap()
    app.buttons["sign-key"].tap()
    let key = app.textFields["subject-key"]
    XCTAssertTrue(key.waitForExistence(timeout: 5))
    key.tap()
    key.typeText(
      "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIFhmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmAAAAEHNzaDplemNyeXB0LXRlc3Q="
    )
    let principals = app.textFields["principals"]
    reveal(principals, in: app)
    principals.tap()
    principals.typeText("alice\n")
    app.buttons["review-certificate"].tap()
    XCTAssertTrue(app.buttons["confirm-sign"].waitForExistence(timeout: 5))
    app.buttons["confirm-sign"].tap()
    XCTAssertTrue(app.buttons["share-certificate"].waitForExistence(timeout: 15))
    reveal(app.buttons["archive-certificate"], in: app)
    app.buttons["archive-certificate"].tap()
    XCTAssertEqual(app.buttons["archive-certificate"].label, "Restore Certificate")
    capture(app, name: "Archived certificate")
    app.buttons["archive-certificate"].tap()
    XCTAssertEqual(app.buttons["archive-certificate"].label, "Archive Certificate")
    app.buttons["delete-certificate"].tap()
    capture(app, name: "Delete certificate confirmation")
    app.buttons["Cancel"].tap()
    XCTAssertTrue(app.buttons["delete-certificate"].exists)
    app.buttons["delete-certificate"].tap()
    app.buttons["Delete Certificate"].tap()
    XCTAssertTrue(app.buttons["sign-key"].waitForExistence(timeout: 5))
    reveal(app.buttons["archive-authority"], in: app)
    app.buttons["archive-authority"].tap()
    XCTAssertTrue(app.buttons["authority-visibility"].waitForExistence(timeout: 5))
    app.buttons["authority-visibility"].tap()
    app.buttons["Archived"].tap()
    try XCTUnwrap(row(name, in: app)).tap()
    reveal(app.buttons["archive-authority"], in: app)
    XCTAssertEqual(app.buttons["archive-authority"].label, "Restore Authority")
    capture(app, name: "Archived authority")
    app.buttons["archive-authority"].tap()
    XCTAssertTrue(app.buttons["authority-visibility"].waitForExistence(timeout: 5))
  }
  /// A trust offer for a valid Ed25519 endpoint nobody listens on, so delivery
  /// stays pending until "Copy instead" cancels it.
  private static let trustURL =
    "ezcrypt://link?v=1&k=trust&n=DXkjIG5OQjn-78xvw45oUCR_EsLgqNtPTCfd9TqVXr4&s=AAECAwQFBgcICQoLDA0ODw&h=testhost&u=alice"
  @MainActor func testTrustOfferCopyInstead() throws {
    let app = XCUIApplication()
    app.launchArguments = ["--demo"]
    app.launch()
    XCTAssertTrue(app.buttons["add-ca"].waitForExistence(timeout: 10))
    let name = "Trust \(UUID().uuidString.prefix(6))"
    app.buttons["add-ca"].tap()
    let nameField = app.textFields["ca-name"]
    XCTAssertTrue(nameField.waitForExistence(timeout: 5))
    nameField.tap()
    nameField.typeText(name + "\n")
    app.buttons["confirm-create-ca"].tap()
    XCTAssertTrue(nameField.waitForNonExistence(timeout: 15))
    app.open(try XCTUnwrap(URL(string: Self.trustURL)))
    XCTAssertTrue(app.staticTexts["alice@testhost"].waitForExistence(timeout: 10))
    let authority = app.buttons.matching(
      NSPredicate(format: "identifier == %@ AND label CONTAINS %@", "link-authority", name)
    ).firstMatch
    reveal(authority, in: app, above: app.buttons["link-send"])
    authority.tap()
    capture(app, name: "Trust offer")
    app.buttons["link-send"].tap()
    let copy = app.buttons["copy-instead"]
    XCTAssertTrue(copy.waitForExistence(timeout: 5))
    // Nobody listens at the endpoint: depending on the network the core keeps
    // trying (waiting) or soon reports the session gone (Try Again). Either way
    // Copy instead stays available.
    let settled = app.descendants(matching: .any).matching(
      NSPredicate(
        format: "(identifier == %@ AND label CONTAINS %@) OR identifier == %@", "delivery-status",
        "Waiting for confirmation on testhost", "delivery-retry")
    ).firstMatch
    XCTAssertTrue(settled.waitForExistence(timeout: 10))
    XCTAssertTrue(copy.exists)
    capture(app, name: "Delivering")
    copy.tap()
    let reply = app.staticTexts["reply-text"]
    XCTAssertTrue(reply.waitForExistence(timeout: 5))
    XCTAssertTrue(reply.label.hasPrefix("ezcrypt1:"), reply.label)
    XCTAssertTrue(app.staticTexts["Paste this into the waiting terminal."].exists)
    capture(app, name: "Reply to paste")
    // Closing must not swap the scanner into the dismissing sheet: it would ask for the camera.
    app.buttons["close-link"].tap()
    XCTAssertTrue(reply.waitForNonExistence(timeout: 5))
    let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    XCTAssertFalse(springboard.alerts.firstMatch.waitForExistence(timeout: 3))
    XCTAssertFalse(app.descendants(matching: .any)["scan-view"].exists)
    XCTAssertTrue(app.buttons["add-ca"].isHittable)
  }
  private static let enrollKey =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
  /// An enroll offer for `enrollKey`, with the trust test's endpoint and secret.
  private static var enrollURL: String {
    let blob = Data(base64Encoded: String(enrollKey.split(separator: " ")[1]))!
    let key = blob.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
    return
      "ezcrypt://link?v=1&k=enroll&n=DXkjIG5OQjn-78xvw45oUCR_EsLgqNtPTCfd9TqVXr4&s=AAECAwQFBgcICQoLDA0ODw&h=testhost&u=alice&p=\(key)"
  }
  @MainActor func testEnrollOfferSignsAndCopies() throws {
    let app = XCUIApplication()
    app.launchArguments = ["--demo"]
    app.launch()
    XCTAssertTrue(app.buttons["add-ca"].waitForExistence(timeout: 10))
    let name = "Enroll \(UUID().uuidString.prefix(6))"
    app.buttons["add-ca"].tap()
    let nameField = app.textFields["ca-name"]
    XCTAssertTrue(nameField.waitForExistence(timeout: 5))
    nameField.tap()
    nameField.typeText(name + "\n")
    app.buttons["confirm-create-ca"].tap()
    XCTAssertTrue(nameField.waitForNonExistence(timeout: 15))
    app.open(try XCTUnwrap(URL(string: Self.enrollURL)))
    XCTAssertTrue(app.staticTexts["alice@testhost"].waitForExistence(timeout: 10))
    let authority = app.buttons.matching(
      NSPredicate(format: "identifier == %@ AND label CONTAINS %@", "link-authority", name)
    ).firstMatch
    reveal(authority, in: app, above: app.buttons["link-send"])
    authority.tap()
    app.buttons["link-send"].tap()
    let key = app.descendants(matching: .any)["subject-key"]
    XCTAssertTrue(key.waitForExistence(timeout: 5))
    XCTAssertEqual(key.label, Self.enrollKey)
    XCTAssertEqual(app.textFields["principals"].value as? String, "alice")
    capture(app, name: "Enroll offer")
    app.buttons["review-certificate"].tap()
    let sign = app.buttons["confirm-sign"]
    reveal(sign, in: app)
    sign.tap()
    let copy = app.buttons["copy-instead"]
    XCTAssertTrue(copy.waitForExistence(timeout: 10))
    let settled = app.descendants(matching: .any).matching(
      NSPredicate(
        format: "(identifier == %@ AND label CONTAINS %@) OR identifier == %@", "delivery-status",
        "Waiting for confirmation on testhost", "delivery-retry")
    ).firstMatch
    XCTAssertTrue(settled.waitForExistence(timeout: 10))
    copy.tap()
    let reply = app.staticTexts["reply-text"]
    XCTAssertTrue(reply.waitForExistence(timeout: 5))
    XCTAssertTrue(reply.label.hasPrefix("ezcrypt1:"), reply.label)
    app.buttons["close-link"].tap()
    XCTAssertTrue(reply.waitForNonExistence(timeout: 5))
    app.tabBars.buttons["Certificates"].tap()
    // The demo inventory outlives each launch, so count by this test's own CA. Each
    // certificate row is one combined element naming its authority.
    let rows = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", name))
    XCTAssertTrue(rows.firstMatch.waitForExistence(timeout: 5))
    XCTAssertEqual(rows.count, 1)
  }
  @MainActor private func fillSigning(
    _ app: XCUIApplication, publicKey: String, capturing: Bool = false
  ) {
    let key = app.textFields["subject-key"]
    XCTAssertTrue(key.waitForExistence(timeout: 5))
    key.tap()
    key.typeText(publicKey)
    if capturing { capture(app, name: "Public key") }
    // Return dismisses the keyboard, uncovering the rows beneath the action bar.
    let principals = app.textFields["principals"]
    reveal(principals, in: app)
    principals.tap()
    principals.typeText("alice\n")
    let unrestricted = app.switches["All principals (advanced)"]
    reveal(unrestricted, in: app, above: app.buttons["review-certificate"])
    flip(unrestricted)
    XCTAssertTrue(
      app.staticTexts.matching(
        NSPredicate(format: "label CONTAINS %@", "Servers using TrustedUserCAKeys reject")
      ).firstMatch.exists)
    flip(unrestricted)
    XCTAssertEqual(principals.value as? String, "alice")
    reveal(app.buttons["validity"], in: app)
    app.buttons["validity"].tap()
    app.buttons["Forever"].tap()
    let keyID = app.textFields["key-id"]
    reveal(keyID, in: app)
    keyID.tap()
    keyID.typeText("workstation")
    if capturing { capture(app, name: "Sign key") }
    reveal(app.buttons["review-certificate"], in: app)
    app.buttons["review-certificate"].tap()
    reveal(app.buttons["confirm-sign"], in: app)
    XCTAssertTrue(app.buttons["confirm-sign"].exists)
  }
  /// Lists create rows lazily, so scroll until the authority's row exists.
  /// NavigationLink accessibility may expose either a button or static text.
  @MainActor private func row(_ name: String, in app: XCUIApplication) -> XCUIElement? {
    let text = app.staticTexts[name].firstMatch
    let button = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", name)).firstMatch
    for _ in 0..<12 {
      if text.exists { return text }
      if button.exists { return button }
      app.swipeUp()
    }
    return nil
  }
  /// Form toggles switch only from the control itself, not the row label.
  @MainActor private func flip(_ toggle: XCUIElement) {
    toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.95, dy: 0.5)).tap()
  }
  /// Scrolls until the element is hittable and, when given, clear of the pinned action bar.
  @MainActor private func reveal(
    _ element: XCUIElement, in app: XCUIApplication, above bar: XCUIElement? = nil
  ) {
    for _ in 0..<8 {
      if element.isHittable
        && (bar.map { !$0.exists || element.frame.maxY <= $0.frame.minY } ?? true)
      {
        return
      }
      app.swipeUp()
    }
  }

  @MainActor private func capture(_ app: XCUIApplication, name: String) {
    let attachment = XCTAttachment(screenshot: app.screenshot())
    attachment.name = name
    attachment.lifetime = .keepAlways
    add(attachment)
  }

}
