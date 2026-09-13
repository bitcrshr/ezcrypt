import SwiftUI

enum Ink {
  static let onAccent = Color(
    light: .white, dark: UIColor(red: 0.04, green: 0.16, blue: 0.12, alpha: 1))
  static let accent = Color(
    light: UIColor(red: 0.08, green: 0.37, blue: 0.29, alpha: 1),
    dark: UIColor(red: 0.47, green: 0.86, blue: 0.69, alpha: 1))
  static let canvas = Color(
    light: UIColor(red: 0.96, green: 0.96, blue: 0.93, alpha: 1),
    dark: UIColor(red: 0.065, green: 0.08, blue: 0.075, alpha: 1))
  static let panel = Color(
    light: .white, dark: UIColor(red: 0.11, green: 0.13, blue: 0.12, alpha: 1))
}
extension Color {
  fileprivate init(light: UIColor, dark: UIColor) {
    self.init(uiColor: UIColor { $0.userInterfaceStyle == .dark ? dark : light })
  }
}
struct Panel<Content: View>: View {
  @ViewBuilder var content: Content
  var body: some View {
    VStack(alignment: .leading, spacing: 16) { content }.padding(20).frame(
      maxWidth: .infinity, alignment: .leading
    ).background(Ink.panel, in: RoundedRectangle(cornerRadius: 22))
  }
}
struct Eyebrow: View {
  let text: String
  var body: some View {
    Text(text.uppercased()).font(.caption.weight(.semibold)).tracking(1.5).foregroundStyle(
      .secondary)
  }
}
struct Fingerprint: View {
  let value: String
  var body: some View {
    Text(value).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
      .textSelection(.enabled).fixedSize(horizontal: false, vertical: true).accessibilityLabel(
        "Fingerprint \(value)")
  }
}
struct StatusPill: View {
  let status: CertificateStatus
  var body: some View {
    Text(status.rawValue).font(.caption.weight(.semibold)).foregroundStyle(
      status == .valid ? Ink.accent : .secondary
    ).padding(.horizontal, 10).padding(.vertical, 5).background(
      (status == .valid ? Ink.accent : Color.secondary).opacity(0.1), in: Capsule())
  }
}
struct LabeledValue: View {
  let title: String
  let value: String
  var body: some View {
    VStack(alignment: .leading, spacing: 5) {
      Text(title).font(.caption).foregroundStyle(.secondary)
      Text(value).textSelection(.enabled)
    }
  }
}
struct PrimaryAction: View {
  @Environment(\.isEnabled) private var isEnabled
  let title: String
  var symbol = "arrow.right"
  var busy = false
  var action: () -> Void
  var body: some View {
    Button(action: action) {
      HStack {
        Text(title).fontWeight(.semibold)
        Spacer()
        if busy { ProgressView().tint(Ink.onAccent) } else { Image(systemName: symbol) }
      }.padding(17)
    }.foregroundStyle(Ink.onAccent).background(
      Ink.accent.opacity(busy ? 0.7 : 1), in: RoundedRectangle(cornerRadius: 16)
    ).disabled(busy).opacity(isEnabled ? 1 : 0.4)
  }
}
extension View {
  func inputStyle() -> some View {
    self.padding(13).background(Ink.canvas, in: RoundedRectangle(cornerRadius: 12))
  }
  func pageStyle() -> some View {
    self.background(Ink.canvas).scrollDismissesKeyboard(.interactively)
  }
}
func dateLabel(_ timestamp: UInt64?) -> String {
  guard let timestamp else { return "Forever" }
  return Date(timeIntervalSince1970: TimeInterval(timestamp)).formatted(
    date: .abbreviated, time: .shortened)
}

struct DemoBanner: View {
  var body: some View {
    if RuntimeMode.demo {
      Label("SIMULATOR · TEST KEYS", systemImage: "hammer").font(.caption2.weight(.semibold))
        .tracking(1).frame(maxWidth: .infinity).padding(7).background(Color.orange.opacity(0.14))
        .accessibilityIdentifier("demo-banner")
    }
  }
}
