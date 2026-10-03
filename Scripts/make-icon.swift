// Generates Resources/AppIcon.icns from vector art, so the icon is rebuildable
// rather than a binary blob nobody can edit.
//
//   swift Scripts/make-icon.swift
//
// Needs no Xcode: it renders with SwiftUI and hands the PNGs to iconutil.
import SwiftUI
import AppKit

// MARK: - Art

/// A local network, reduced to its bones: the router on top, one shared line,
/// and the devices hanging off it — the one Dozor has just found, in green.
/// Few shapes and thick strokes, so it still reads at 16 px.
struct IconArt: View {
    let side: CGFloat
    /// Below 128 px thin strokes turn to mush, so small sizes get heavier lines
    /// rather than a blurred version of the large drawing.
    var simplified: Bool = false

    /// Apple's icon grid: the plate is 824 pt inside a 1024 pt canvas.
    private var plate: CGFloat { side * 0.8047 }
    private var corner: CGFloat { plate * 0.2237 }
    private var shape: RoundedRectangle {
        RoundedRectangle(cornerRadius: corner, style: .continuous)
    }

    var body: some View {
        ZStack {
            shape
                .fill(LinearGradient(
                    colors: [Color(red: 0.10, green: 0.14, blue: 0.30),
                             Color(red: 0.12, green: 0.36, blue: 0.78)],
                    startPoint: .top, endPoint: .bottom))
                .overlay {
                    // A little light along the top edge, so the plate reads as a
                    // surface rather than a flat swatch.
                    shape.fill(LinearGradient(colors: [.white.opacity(0.14), .clear],
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
            let w = size.width
            let line = w * (simplified ? 0.075 : 0.05)
            let stroke = StrokeStyle(lineWidth: line, lineCap: .round, lineJoin: .round)
            let white = Color.white
            let green = Color(red: 0.19, green: 0.84, blue: 0.40)

            // Router: a rounded box at the top centre.
            let routerSize = CGSize(width: w * 0.30, height: w * 0.19)
            let router = CGRect(x: (w - routerSize.width) / 2, y: w * 0.17,
                                width: routerSize.width, height: routerSize.height)
            context.fill(Path(roundedRect: router, cornerRadius: w * 0.045), with: .color(white))

            // Device positions along the bottom.
            let busY = w * 0.56
            let deviceY = w * 0.74
            let xs = [w * 0.24, w * 0.50, w * 0.76]

            var wires = Path()
            wires.move(to: CGPoint(x: w / 2, y: router.maxY))
            wires.addLine(to: CGPoint(x: w / 2, y: busY))
            wires.move(to: CGPoint(x: xs[0], y: deviceY))
            wires.addLine(to: CGPoint(x: xs[0], y: busY))
            wires.addLine(to: CGPoint(x: xs[2], y: busY))
            wires.addLine(to: CGPoint(x: xs[2], y: deviceY))
            wires.move(to: CGPoint(x: xs[1], y: busY))
            wires.addLine(to: CGPoint(x: xs[1], y: deviceY))
            context.stroke(wires, with: .color(white.opacity(0.85)), style: stroke)

            let radius = w * (simplified ? 0.085 : 0.075)
            for (index, x) in xs.enumerated() {
                let box = CGRect(x: x - radius, y: deviceY - radius,
                                 width: radius * 2, height: radius * 2)
                context.fill(Path(ellipseIn: box), with: .color(index == 2 ? green : white))
            }
        }
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
