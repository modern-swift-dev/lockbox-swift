# Lockbox

Lockbox is a small, type-safe Swift wrapper around Apple Keychain Services and Local Authentication. It stores generic and internet passwords, supports raw `Data`, builds keychain queries from Swift enum values, and provides an iOS biometric credential service.

Read the [Lockbox documentation](https://modern-swift-dev.github.io/docs/lockbox-swift/) for guides, examples, and API reference.

## Requirements

- Swift 6
- macOS 15+, iOS 18+, tvOS 18+, watchOS 10+, or visionOS 1+

Some APIs have narrower platform availability. The [documentation hub](https://modern-swift-dev.github.io/docs/lockbox-swift/documentation/) lists those limits.

## Installation

Add `https://github.com/modern-swift-dev/lockbox-swift.git` as a Swift Package dependency in Xcode, then add the `Lockbox` product to your target.

For a package manifest, add the dependency and product:

```swift
dependencies: [
    .package(
        url: "https://github.com/modern-swift-dev/lockbox-swift.git",
        from: "1.0.0"
    )
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: ["Lockbox"]
    )
]
```

Then import the library:

```swift
import Lockbox
```

## Quick start

```swift
let password = KeychainPassword.generic(
    service: "com.example.account",
    account: "person@example.com"
)

try password.set(string: "a-secret")
let savedPassword = try password.getString()
try password.remove()
```

`set(string:)` and `set(data:)` create an item or update an existing match. Read methods return `nil` when an item does not exist.

See the [getting started guide](https://modern-swift-dev.github.io/docs/lockbox-swift/documentation/getting-started/) for the complete workflow and the [examples](https://modern-swift-dev.github.io/docs/lockbox-swift/examples/) for generic passwords, internet passwords, typed queries, and biometric credentials.

## Contributing

Guides and examples live in [Documentation/Site](Documentation/Site). The [central documentation repository](https://github.com/modern-swift-dev/docs) owns the shared Astro theme, builds the guides and DocC API reference, and publishes them daily. For local builds and previews, follow the [docs README](https://github.com/modern-swift-dev/docs/blob/main/README.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) for contributor instructions.

## License

Lockbox is available under the MIT License. See [LICENSE](LICENSE).
