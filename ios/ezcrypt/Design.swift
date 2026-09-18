import SwiftUI

/// One ink, used sparingly: stamp-pad ultramarine. Everything else is system
/// material so lists, sheets, and glass stay native in both appearances.
enum Ink {
  static let accent = Color(light: 0x3446C8, dark: 0x9BA8FF)
  /// Label color on a filled accent surface.
  static let onAccent = Color(light: 0xFFFFFF, dark: 0x0D1233)
}
extension Color {
  fileprivate init(light: UInt32, dark: UInt32) {
    #if os(macOS)
      func color(_ hex: UInt32) -> NSColor {
        NSColor(
          srgbRed: CGFloat(hex >> 16 & 0xFF) / 255,
          green: CGFloat(hex >> 8 & 0xFF) / 255,
          blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
      }
      self.init(
        nsColor: NSColor(name: nil) { appearance in
          appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? color(dark) : color(light)
        })
    #else
      func color(_ hex: UInt32) -> UIColor {
        UIColor(
          red: CGFloat(hex >> 16 & 0xFF) / 255,
          green: CGFloat(hex >> 8 & 0xFF) / 255,
          blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
      }
      self.init(uiColor: UIColor { $0.userInterfaceStyle == .dark ? color(dark) : color(light) })
    #endif
  }
}

extension CertificateStatus {
  var tint: Color {
    switch self {
    case .valid: .green
    case .scheduled: Ink.accent
    case .expired: .secondary
    }
  }
  var symbol: String {
    switch self {
    case .valid: "checkmark.seal.fill"
    case .scheduled: "clock.fill"
    case .expired: "xmark.seal"
    }
  }
}

// MARK: Randomart

/// OpenSSH's "drunken bishop" fingerprint visualization, identical to the
/// art printed by `ssh-keygen -lv` for the same SHA-256 fingerprint.
struct Randomart {
  static let columns = 17
  static let rows = 9
  private static let symbols = Array(" .o+=*BOX@%&#/^SE")
  static let start = symbols.count - 2
  static let end = symbols.count - 1
  let cells: [Int]

  init?(fingerprint: String) {
    guard fingerprint.hasPrefix("SHA256:") else { return nil }
    var encoded = String(fingerprint.dropFirst(7))
    while encoded.count % 4 != 0 { encoded += "=" }
    guard let digest = Data(base64Encoded: encoded), !digest.isEmpty else { return nil }
    var cells = Array(repeating: 0, count: Self.columns * Self.rows)
    var x = Self.columns / 2
    var y = Self.rows / 2
    for byte in digest {
      var input = Int(byte)
      for _ in 0..<4 {
        x = min(max(x + (input & 1 == 1 ? 1 : -1), 0), Self.columns - 1)
        y = min(max(y + (input & 2 == 2 ? 1 : -1), 0), Self.rows - 1)
        if cells[y * Self.columns + x] < Self.symbols.count - 3 { cells[y * Self.columns + x] += 1 }
        input >>= 2
      }
    }
    cells[Self.rows / 2 * Self.columns + Self.columns / 2] = Self.start
    cells[y * Self.columns + x] = Self.end
    self.cells = cells
  }
  func level(_ x: Int, _ y: Int) -> Int { cells[y * Self.columns + x] }
  func row(_ y: Int) -> String {
    String((0..<Self.columns).map { Self.symbols[level($0, y)] })
  }
  static func border(_ label: String) -> String {
    let left = (columns - label.count) / 2
    return "+" + String(repeating: "-", count: left) + label
      + String(repeating: "-", count: columns - left - label.count) + "+"
  }
  func text(title: String) -> String {
    ([Self.border("[\(title)]")] + (0..<Self.rows).map { "|\(row($0))|" } + [
      Self.border("[SHA256]")
    ]).joined(separator: "\n")
  }
}
extension KeyAlgorithm {
  /// The `[TYPE BITS]` label `ssh-keygen -lv` prints above the art.
  var randomartTitle: String {
    switch self {
    case .ed25519: "ED25519 256"
    case .p256: "ECDSA 256"
    case .p384: "ECDSA 384"
    case .p521: "ECDSA 521"
    }
  }
}

/// The full ASCII art, framed exactly as OpenSSH prints it. Fixed size: it is
/// a picture, and reflowing it under Dynamic Type would destroy it.
struct RandomartView: View {
  let fingerprint: String
  let algorithm: KeyAlgorithm
  var body: some View {
    if let art = Randomart(fingerprint: fingerprint) {
      VStack(spacing: 0) {
        Text(Randomart.border("[\(algorithm.randomartTitle)]")).foregroundStyle(.tertiary)
        ForEach(0..<Randomart.rows, id: \.self) { y in
          Text(
            "\(Text("|").foregroundStyle(.tertiary))\(art.row(y))\(Text("|").foregroundStyle(.tertiary))"
          )
        }
        Text(Randomart.border("[SHA256]")).foregroundStyle(.tertiary)
      }
      .font(.system(size: 15, weight: .medium, design: .monospaced))
      .foregroundStyle(Ink.accent)
      .fixedSize()
      .accessibilityElement()
      .accessibilityLabel("Fingerprint art")
      .accessibilityHint("Matches ssh-keygen -lv for this key")
    }
  }
}

/// The same walk drawn as a dot matrix: a compact, recognizable mark for an
/// authority in lists.
struct Seal: View {
  let fingerprint: String
  var body: some View {
    let art = Randomart(fingerprint: fingerprint)
    Canvas { context, size in
      guard let art else { return }
      let cell = min(size.width / CGFloat(Randomart.columns), size.height / CGFloat(Randomart.rows))
      let origin = CGPoint(
        x: (size.width - cell * CGFloat(Randomart.columns)) / 2,
        y: (size.height - cell * CGFloat(Randomart.rows)) / 2)
      for y in 0..<Randomart.rows {
        for x in 0..<Randomart.columns {
          let level = art.level(x, y)
          let center = CGPoint(
            x: origin.x + (CGFloat(x) + 0.5) * cell, y: origin.y + (CGFloat(y) + 0.5) * cell)
          let radius: CGFloat
          let opacity: Double
          switch level {
          case 0:
            (radius, opacity) = (cell * 0.12, 0.25)
          case Randomart.start, Randomart.end:
            (radius, opacity) = (cell * 0.5, 1)
          default:
            (radius, opacity) = (
              cell * (0.24 + 0.05 * CGFloat(min(level, 5))), 0.55 + 0.09 * Double(min(level, 5))
            )
          }
          context.opacity = opacity
          context.fill(
            Path(
              ellipseIn: CGRect(
                x: center.x - radius, y: center.y - radius, width: radius * 2, height: radius * 2)),
            with: .style(Ink.accent))
        }
      }
    }
    .accessibilityHidden(true)
  }
}

/// A seal set on a faint ink tile, sized for a list row.
struct SealTile: View {
  let fingerprint: String
  var body: some View {
    Seal(fingerprint: fingerprint).frame(width: 52, height: 28).padding(8)
      .background(Ink.accent.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
  }
}

// MARK: Controls

/// Full-width primary action, pinned above the home indicator by `actionBar`.
struct PrimaryButton: View {
  let title: String
  var symbol: String?
  var busy = false
  var action: () -> Void
  var body: some View {
    Button(action: action) {
      Group {
        if busy {
          ProgressView().tint(Ink.onAccent)
        } else if let symbol {
          Label(title, systemImage: symbol)
        } else {
          Text(title)
        }
      }
      .fontWeight(.semibold).foregroundStyle(Ink.onAccent).lineLimit(1).minimumScaleFactor(0.7)
      .frame(maxWidth: .infinity)
      .padding(.vertical, 4)
    }
    .buttonStyle(.glassProminent).controlSize(.large).disabled(busy)
  }
}
extension View {
  /// Pins the screen's main action to the bottom edge, always within reach.
  @ViewBuilder func actionBar<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
    #if os(macOS)
      safeAreaInset(edge: .bottom, spacing: 0) {
        VStack(spacing: 10) { content() }.padding(16)
          .frame(maxWidth: .infinity).background(.bar)
      }
    #else
      safeAreaBar(edge: .bottom) {
        VStack(spacing: 10) { content() }.padding(.horizontal, 20).padding(.bottom, 8)
      }
    #endif
  }
}

struct CopyButton: View {
  let title: String
  let value: () throws -> String
  var onError: (Error) -> Void = { _ in }
  var expands = false
  @State private var copied = false
  init(_ title: String, value: @escaping @autoclosure () -> String, expands: Bool = false) {
    self.title = title
    self.value = value
    self.expands = expands
  }
  init(_ title: String, value: @escaping () throws -> String, onError: @escaping (Error) -> Void) {
    self.title = title
    self.value = value
    self.onError = onError
  }
  var body: some View {
    Button {
      do {
        PlatformUI.copy(try value())
        copied = true
      } catch { onError(error) }
    } label: {
      Label(copied ? "Copied" : title, systemImage: copied ? "checkmark" : "document.on.document")
        .contentTransition(.symbolEffect(.replace))
        .frame(maxWidth: expands ? .infinity : nil)
    }
    .sensoryFeedback(.success, trigger: copied) { _, new in new }
    .task(id: copied) {
      guard copied else { return }
      try? await Task.sleep(for: .seconds(2))
      copied = false
    }
  }
}

/// A short value: quiet label, and the value itself in primary ink. Tokens
/// (anything a person would paste into a terminal) are monospaced.
struct ValueRow: View {
  let title: String
  let value: String
  var token = true
  var body: some View {
    LabeledContent {
      Text(value).font(token ? .body.monospaced() : .body).foregroundStyle(.primary)
        .multilineTextAlignment(.trailing).textSelection(.enabled)
    } label: {
      Text(title).foregroundStyle(.secondary)
    }
  }
}
/// A long token such as a fingerprint or key, set below its label so it can
/// wrap without fighting the label for width.
struct TokenBlock: View {
  let title: String
  let value: String
  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(title).font(.subheadline).foregroundStyle(.secondary)
      Text(value).font(.callout.monospaced()).textSelection(.enabled)
        .fixedSize(horizontal: false, vertical: true)
    }
    .padding(.vertical, 2)
    .accessibilityElement(children: .combine)
  }
}

struct StatusLabel: View {
  let status: CertificateStatus
  var body: some View {
    Label(status.rawValue, systemImage: status.symbol).font(.subheadline.weight(.semibold))
      .foregroundStyle(status.tint)
  }
}

// MARK: Dates

func dateLabel(_ timestamp: UInt64?) -> String {
  guard let timestamp else { return "Forever" }
  return Date(timeIntervalSince1970: TimeInterval(timestamp)).formatted(
    date: .abbreviated, time: .shortened)
}
/// "Expires in 3 days", "Expired yesterday", "Starts in 2 hours", "Never expires".
func validitySummary(_ request: SigningRequest, at now: Date) -> String {
  let formatter = RelativeDateTimeFormatter()
  formatter.dateTimeStyle = .named
  func relative(_ timestamp: UInt64) -> String {
    formatter.localizedString(
      for: Date(timeIntervalSince1970: TimeInterval(timestamp)), relativeTo: now)
  }
  let current = UInt64(max(0, now.timeIntervalSince1970))
  if current < request.validAfter { return "Starts \(relative(request.validAfter))" }
  guard let end = request.validBefore else { return "Never expires" }
  return current >= end ? "Expired \(relative(end))" : "Expires \(relative(end))"
}
/// Quiet unless it needs attention: about to expire, or not yet started.
func validityTint(_ request: SigningRequest, at now: Date) -> Color {
  let current = UInt64(max(0, now.timeIntervalSince1970))
  if current < request.validAfter { return Ink.accent }
  if let end = request.validBefore, current < end, end - current < 86400 { return .orange }
  return .secondary
}

struct DemoBanner: View {
  var body: some View {
    if RuntimeMode.demo {
      Label("SIMULATOR · TEST KEYS", systemImage: "hammer.fill").font(.caption2.weight(.bold))
        .tracking(0.8).foregroundStyle(.orange).frame(maxWidth: .infinity).padding(.vertical, 5)
        .background(Color.orange.opacity(0.12)).dynamicTypeSize(...DynamicTypeSize.xxLarge)
        .accessibilityIdentifier("demo-banner")
    }
  }
}
