import XCTest

final class EzcryptUITests: XCTestCase {
  @MainActor func testCreateSignInspectDuplicateExportAndRelaunch() throws {
    let app = XCUIApplication()
    app.launchArguments = ["--demo"]
    app.launch()
    XCTAssertTrue(app.staticTexts["demo-banner"].waitForExistence(timeout: 10))
    let name = "Lab \(UUID().uuidString.prefix(6))"
    app.buttons["add-ca"].tap()
    let nameField = app.textFields["ca-name"]
    XCTAssertTrue(nameField.waitForExistence(timeout: 5))
    nameField.tap()
    nameField.typeText(name)
    app.buttons["custody-software"].tap()
    reveal(app.buttons["confirm-create-ca"], in: app)
    app.buttons["confirm-create-ca"].tap()
    let card = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", name)).firstMatch
    // NavigationLink accessibility may expose either a button or static text.
    let ca = app.staticTexts[name].firstMatch
    XCTAssertTrue(ca.waitForExistence(timeout: 15) || card.waitForExistence(timeout: 2))
    if ca.exists { ca.tap() } else { card.tap() }
    XCTAssertTrue(app.buttons["sign-key"].waitForExistence(timeout: 5))
    capture(app, name: "Authority")
    app.buttons["sign-key"].tap()
    let publicKey =
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    fillSigning(app, publicKey: publicKey)
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
    XCTAssertTrue(app.staticTexts[name].firstMatch.waitForExistence(timeout: 10))
    app.tabBars.buttons["Certificates"].tap()
    XCTAssertTrue(app.staticTexts["workstation"].firstMatch.waitForExistence(timeout: 5))
  }
  @MainActor private func fillSigning(_ app: XCUIApplication, publicKey: String) {
    let key = app.textFields["subject-key"]
    XCTAssertTrue(key.waitForExistence(timeout: 5))
    key.tap()
    key.typeText(publicKey)
    let principals = app.textFields["principals"]
    reveal(principals, in: app)
    let unrestricted = app.switches["All principals (advanced)"]
    reveal(unrestricted, in: app)
    unrestricted.tap()
    XCTAssertTrue(
      app.staticTexts.matching(
        NSPredicate(format: "label CONTAINS %@", "Servers using TrustedUserCAKeys reject")
      ).firstMatch.exists)
    unrestricted.tap()
    reveal(principals, in: app)
    principals.tap()
    principals.typeText("alice")
    reveal(app.buttons["validity"], in: app)
    app.buttons["validity"].tap()
    app.buttons["Forever"].tap()
    let keyID = app.textFields["key-id"]
    reveal(keyID, in: app)
    keyID.tap()
    keyID.typeText("workstation")
    reveal(app.buttons["review-certificate"], in: app)
    app.buttons["review-certificate"].tap()
    reveal(app.buttons["confirm-sign"], in: app)
    XCTAssertTrue(app.buttons["confirm-sign"].exists)
  }
  @MainActor private func reveal(_ element: XCUIElement, in app: XCUIApplication) {
    for _ in 0..<8 {
      if element.isHittable { return }
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
