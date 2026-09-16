// Generates Resources/AppIcon.icns from vector art, so the icon is rebuildable
// rather than a binary blob nobody can edit.
//
//   swift Scripts/make-icon.swift
//
// Needs no Xcode: it renders with SwiftUI and hands the PNGs to iconutil.
import SwiftUI
import AppKit

// MARK: - Art

/// Host discovery, drawn literally: this Mac at the centre, concentric sweeps
/// reaching outward, and the hosts they find sitting on them — one already
/// answering, in green.
struct IconArt: View {
    let side: CGFloat
    /// Below 128 px the rings and thin links turn to mush, so small sizes get a
    /// deliberately coarser drawing rather than a blurred version of this one.
    var simplified: Bool = false

    /// Apple's icon grid: the plate is 824 pt inside a 1024 pt canvas.
    private var plate: CGFloat { side * 0.8047 }
    private var corner: CGFloat { plate * 0.2237 }
    private var shape: RoundedRectangle {
        RoundedRectangle(cornerRadius: corner, style: .continuous)
    }

    /// Angle in degrees (0 = right) and the ring the host sits on.
    private var nodes: [(angle: Double, ring: Int, found: Bool)] {
        simplified
            ? [(325, 1, true)]
            : [(205, 0, false), (20, 0, false), (150, 1, false), (255, 1, false), (325, 1, true)]
    }

    private var ringRadii: [CGFloat] {
        simplified ? [0.30] : [0.175, 0.30, 0.415]
    }

    var body: some View {
        ZStack {
            shape
                .fill(LinearGradient(
                    colors: [Color(red: 0.11, green: 0.16, blue: 0.38),
                             Color(red: 0.13, green: 0.44, blue: 0.87)],
                    startPoint: .topLeading, endPoint: .bottomTrailing))
                .overlay {
                    // A little light along the top edge, so the plate reads as a
                    // surface rather than a flat swatch.
                    shape.fill(LinearGradient(colors: [.white.opacity(0.18), .clear],
                                              startPoint: .top, endPoint: .center))
                }
                .overlay { artwork }
                .clipShape(shape)
                .frame(width: plate, height: plate)
                .shadow(color: .black.opacity(0.25), radius: side * 0.016, y: side * 0.010)
        }
        .frame(width: side, height: side)
    }

    private var artwork: some View {
        Canvas { context, size in
            let centre = CGPoint(x: size.width / 2, y: size.height / 2)

            for (index, radius) in ringRadii.enumerated() {
                let diameter = size.width * radius * 2
                let box = CGRect(x: centre.x - diameter / 2, y: centre.y - diameter / 2,
                                 width: diameter, height: diameter)
                context.stroke(
                    Path(ellipseIn: box),
                    with: .color(.white.opacity(simplified ? 0.34 : 0.30 - Double(index) * 0.06)),
                    lineWidth: size.width * (simplified ? 0.045 : 0.020)
                )
            }

            for node in nodes {
                var link = Path()
                link.move(to: centre)
                link.addLine(to: point(for: node, centre: centre, size: size))
                context.stroke(link, with: .color(.white.opacity(0.40)),
                               lineWidth: size.width * 0.013)
            }

            for node in nodes {
                let position = point(for: node, centre: centre, size: size)
                let radius = size.width * (simplified ? 0.065 : 0.045)
                let box = CGRect(x: position.x - radius, y: position.y - radius,
                                 width: radius * 2, height: radius * 2)
                let colour: Color = node.found
                    ? Color(red: 0.19, green: 0.82, blue: 0.35)
                    : .white
                context.fill(Path(ellipseIn: box), with: .color(colour))
            }

            // This Mac, at the centre of its own sweep.
            let hub = size.width * (simplified ? 0.085 : 0.058)
            context.fill(Path(ellipseIn: CGRect(x: centre.x - hub, y: centre.y - hub,
                                                width: hub * 2, height: hub * 2)),
                         with: .color(.white))
        }
    }

    private func point(for node: (angle: Double, ring: Int, found: Bool),
                       centre: CGPoint, size: CGSize) -> CGPoint {
        let radius = size.width * ringRadii[min(node.ring, ringRadii.count - 1)]
        let radians = node.angle * .pi / 180
        return CGPoint(x: centre.x + cos(radians) * radius,
                       y: centre.y + sin(radians) * radius)
    }
}

// MARK: - Output

@MainActor
func renderPNG(side: CGFloat, simplified: Bool, to url: URL) {
    let renderer = ImageRenderer(content: IconArt(side: side, simplified: simplified))
    renderer.scale = 1
    renderer.isOpaque = false
    guard let image = renderer.nsImage,
          let tiff = image.tiffRepresentation,
          let bitmap = NSBitmapImageRep(data: tiff),
          let png = bitmap.representation(using: .png, properties: [:])
    else {
        FileHandle.standardError.write(Data("failed to render \(Int(side))px\n".utf8))
        return
    }
    try? png.write(to: url)
}

MainActor.assumeIsolated {
    let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    let iconset = root.appendingPathComponent("build/AppIcon.iconset")
    let resources = root.appendingPathComponent("Resources")
    try? FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
    try? FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)

    // name, pixel size
    let entries: [(String, CGFloat)] = [
        ("icon_16x16", 16), ("icon_16x16@2x", 32),
        ("icon_32x32", 32), ("icon_32x32@2x", 64),
        ("icon_128x128", 128), ("icon_128x128@2x", 256),
        ("icon_256x256", 256), ("icon_256x256@2x", 512),
        ("icon_512x512", 512), ("icon_512x512@2x", 1024),
    ]
    for (name, pixels) in entries {
        renderPNG(side: pixels, simplified: pixels < 128,
                  to: iconset.appendingPathComponent("\(name).png"))
    }
    // A full-size preview that is easy to open and look at.
    renderPNG(side: 512, simplified: false, to: root.appendingPathComponent("build/icon-preview.png"))

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
    process.arguments = ["-c", "icns", iconset.path,
                         "-o", resources.appendingPathComponent("AppIcon.icns").path]
    try? process.run()
    process.waitUntilExit()
    print(process.terminationStatus == 0
          ? "wrote Resources/AppIcon.icns"
          : "iconutil failed with \(process.terminationStatus)")
}
