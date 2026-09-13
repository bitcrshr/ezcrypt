set shell := ["zsh", "-eu", "-c"]
export CARGO_HOME := justfile_directory() / ".build/cargo"
project := "ios/ezcrypt.xcodeproj"
simulator := "iPhone 17 Pro"

# List the development tasks.
default:
    @just --list

# Install Rust iOS targets and download locked dependencies locally.
bootstrap:
    rustup target add aarch64-apple-ios aarch64-apple-ios-sim
    cargo fetch --locked

# Rust validation, including OpenSSH/GnuPG recovery with disposable local keys.
test-core:
    cargo test --locked
    cargo clippy --locked --all-targets -- -D warnings
    cargo fmt --all -- --check

# Build the iOS app for an Apple Silicon Simulator.
build-ios:
    xcodebuild -project {{project}} -scheme ezcrypt -configuration Debug -destination 'platform=iOS Simulator,name={{simulator}}' -derivedDataPath .build/xcode build

# Swift integration and UI tests; hardware stand-ins are Debug Simulator only.
test-ios:
    xcodebuild -project {{project}} -scheme ezcrypt -configuration Debug -destination 'platform=iOS Simulator,name={{simulator}}' -derivedDataPath .build/xcode -parallel-testing-enabled NO test

# Compile the real device code path without signing or installing.
check-device:
    xcodebuild -project {{project}} -scheme ezcrypt -configuration Release -destination 'generic/platform=iOS' -derivedDataPath .build/device CODE_SIGNING_ALLOWED=NO build

# Open the checked-in Xcode project. Choose a signing team for physical devices.
xcode:
    open {{project}}

# Rebuild the app icon from its vector construction.
icon:
    xcrun swift -module-cache-path .build/swift-modules ios/Tools/render-icon.swift ios/ezcrypt/Assets.xcassets/AppIcon.appiconset/AppIcon.png

# Format the shared core and Swift sources.
fmt:
    cargo fmt --all
    xcrun swift-format format --in-place --recursive ios/ezcrypt ios/ezcryptTests ios/ezcryptUITests ios/Tools
