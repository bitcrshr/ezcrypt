set shell := ["zsh", "-eu", "-c"]
export CARGO_HOME := justfile_directory() / ".build/cargo"
project := "ios/ezcrypt.xcodeproj"
simulator := "iPhone 17 Pro"

# List the development tasks.
default:
    @just --list

# Install Rust Apple targets and download locked dependencies locally.
bootstrap:
    rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin
    cargo fetch --locked

# Rust validation, including OpenSSH/GnuPG recovery with disposable local keys.
test-core:
    cargo test --locked
    cargo clippy --locked --all-targets -- -D warnings
    cargo fmt --all -- --check

# End-to-end `ezcrypt trust` against sshd in a container (needs Docker).
test-trust:
    tests/trust/run.sh

# Run the CLI from source: `just cli enroll --key /tmp/k`, `just cli update --check`.
[no-cd]
[positional-arguments]
cli *args:
    @cargo run --locked -q -p ezcrypt-cli -- "$@"

# Build the iOS app for an Apple Silicon Simulator.
build-ios:
    id=$(xcrun simctl list devices available | awk -F'[()]' '/ {{simulator}} \(/{print $2; exit}'); [ -n "$id" ] || { echo "No available Simulator named {{simulator}}" >&2; exit 1; }; xcodebuild -project {{project}} -scheme ezcrypt -configuration Debug -destination "platform=iOS Simulator,id=$id" -derivedDataPath .build/xcode build

# Swift integration and UI tests; hardware stand-ins are Debug Simulator only.
test-ios:
    id=$(xcrun simctl list devices available | awk -F'[()]' '/ {{simulator}} \(/{print $2; exit}'); [ -n "$id" ] || { echo "No available Simulator named {{simulator}}" >&2; exit 1; }; xcodebuild -project {{project}} -scheme ezcrypt -configuration Debug -destination "platform=iOS Simulator,id=$id" -derivedDataPath .build/xcode -parallel-testing-enabled NO test

# Compile the real device code path without signing or installing.
check-device:
    xcodebuild -project {{project}} -scheme ezcrypt -configuration Release -destination 'generic/platform=iOS' -derivedDataPath .build/device CODE_SIGNING_ALLOWED=NO build

# Open the checked-in Xcode project. For physical devices, set DEVELOPMENT_TEAM in ios/Config/Signing.local.xcconfig.
xcode:
    open {{project}}

# Rebuild the app icon from its vector construction.
icon:
    xcrun swift -module-cache-path .build/swift-modules ios/Tools/render-icon.swift ios/ezcrypt/Assets.xcassets/AppIcon.appiconset/AppIcon.png

# Format the shared core and Swift sources.
fmt:
    cargo fmt --all
    xcrun swift-format format --in-place --recursive ios/ezcrypt ios/ezcryptTests ios/ezcryptUITests ios/ezcryptMacTests ios/Tools

# Native Apple silicon Mac build. Set DEVELOPMENT_TEAM in ios/Config/Signing.local.xcconfig for real key use.
build-mac *args="":
    xcodebuild -project {{project}} -scheme ezcryptMac -configuration Debug -destination 'platform=macOS,arch=arm64' -derivedDataPath .build/mac build {{args}}

# Native filesystem/model checks with local signing; no Keychain entitlement or hardware operations.
test-mac:
    xcodebuild -project {{project}} -scheme ezcryptMac -configuration Debug -destination 'platform=macOS,arch=arm64' -derivedDataPath .build/mac CODE_SIGN_IDENTITY=- CODE_SIGN_ENTITLEMENTS=Mac/ezcryptMac-local.entitlements test

# Compile the native Mac Release path without requiring signing credentials.
check-mac:
    xcodebuild -project {{project}} -scheme ezcryptMac -configuration Release -destination 'platform=macOS,arch=arm64' -derivedDataPath .build/mac-release CODE_SIGNING_ALLOWED=NO build
