#!/bin/bash
# Builds Dozor.app. Xcode is not required — the app bundle is assembled by
# hand around the SwiftPM executable and signed ad-hoc so it launches locally.
set -euo pipefail

CONFIG="${1:-release}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/build/Dozor.app"
VERSION="${VERSION:-0.0.1}"

# ARCHS="arm64 x86_64" builds a universal binary; empty means the host arch.
ARCH_FLAGS=()
for arch in ${ARCHS:-}; do
    ARCH_FLAGS+=(--arch "$arch")
done

cd "$ROOT"
swift build -c "$CONFIG" --product Dozor ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"}

BIN="$(swift build -c "$CONFIG" --product Dozor ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} --show-bin-path)/Dozor"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Dozor"

# The icon is vector art rendered by Scripts/make-icon.swift, so it is built
# rather than committed as a binary nobody can edit.
if [ ! -f "$ROOT/Resources/AppIcon.icns" ]; then
    swift "$ROOT/Scripts/make-icon.swift" >/dev/null
fi
cp "$ROOT/Resources/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Dozor</string>
    <key>CFBundleDisplayName</key><string>Dozor</string>
    <key>CFBundleIdentifier</key><string>dev.dozor.app</string>
    <key>CFBundleExecutable</key><string>Dozor</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleIconName</key><string>AppIcon</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSHumanReadableCopyright</key><string>Local network scanning front-end for Nmap.</string>
    <key>NSLocalNetworkUsageDescription</key><string>Dozor probes addresses on this Mac's own subnet to show which devices answer and reads the ARP table to learn their hardware addresses. Nothing outside the local network is contacted.</string>
    <key>NSPrincipalClass</key><string>NSApplication</string>
    <key>NSSupportsAutomaticTermination</key><false/>
    <key>NSSupportsSuddenTermination</key><false/>
</dict>
</plist>
PLIST

printf 'APPL????' > "$APP/Contents/PkgInfo"

# Ad-hoc signature. The app is not sandboxed: it must launch /opt/homebrew/bin/nmap,
# which a sandboxed process cannot do.
codesign --force --sign - --timestamp=none "$APP" >/dev/null 2>&1 || {
    echo "warning: ad-hoc signing failed; the app may still run" >&2
}

echo "built $APP"
