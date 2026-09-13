import AppKit
import ImageIO
import UniformTypeIdentifiers

// Vector construction: a compact key, matching the app's ink and mint palette.
let size = 1024
let context = CGContext(
  data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: size * 4,
  space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
context.setFillColor(CGColor(red: 0.055, green: 0.24, blue: 0.19, alpha: 1))
context.fill(CGRect(x: 0, y: 0, width: size, height: size))
context.setStrokeColor(CGColor(red: 0.69, green: 0.95, blue: 0.79, alpha: 1))
context.setLineWidth(66)
context.setLineCap(.round)
context.setLineJoin(.round)
context.strokeEllipse(in: CGRect(x: 500, y: 360, width: 300, height: 300))
context.move(to: CGPoint(x: 500, y: 510))
context.addLine(to: CGPoint(x: 235, y: 510))
context.strokePath()
for x in [280, 385] {
  context.move(to: CGPoint(x: x, y: 510))
  context.addLine(to: CGPoint(x: x, y: 425))
  context.strokePath()
}
context.setFillColor(CGColor(red: 0.69, green: 0.95, blue: 0.79, alpha: 1))
context.fillEllipse(in: CGRect(x: 625, y: 485, width: 50, height: 50))
let url = URL(fileURLWithPath: CommandLine.arguments[1])
let destination = CGImageDestinationCreateWithURL(
  url as CFURL, UTType.png.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(destination, context.makeImage()!, nil)
precondition(CGImageDestinationFinalize(destination))
