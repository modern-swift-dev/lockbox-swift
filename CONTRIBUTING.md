# Contributing

## Website releases

Guides and examples live in [Documentation/Site](Documentation/Site). The [central documentation repository](https://github.com/modern-swift-dev/docs) owns the shared Astro theme, builds the guides and DocC API reference, and publishes them daily. For local builds and previews, follow the [docs README](https://github.com/modern-swift-dev/docs/blob/main/README.md).

Keep Markdown guides, example source, and Swift documentation comments in this module. Publish a GitHub release to update the version and release information on the next daily build. Commit documentation sources only.

## DocC plugin dependency

`Package.swift` depends on [`swift-docc-plugin`](https://github.com/swiftlang/swift-docc-plugin) only for the central documentation build. That build runs `swift package generate-documentation --target Lockbox` in this repository's checkout (see `scripts/build-api.ts` in the [docs repository](https://github.com/modern-swift-dev/docs)), and SwiftPM only offers that command when the package itself depends on the plugin. Keep the dependency unless the docs repository stops using the plugin.

`make documentation` (`Scripts/build-documentation.sh`) uses `xcodebuild docbuild` instead, which doesn't need the plugin.
