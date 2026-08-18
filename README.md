# Lockbox

Lockbox is a small, type-safe Swift wrapper around Apple Keychain Services and Local Authentication. It stores generic or internet passwords, supports raw `Data`, builds keychain queries from Swift enum values, and offers an iOS biometric credential service.

## Requirements

- Swift 6
- macOS 15+, iOS 18+, tvOS 18+, watchOS 10+, or visionOS 1+

Some APIs have narrower availability. See [Platform availability](docs/README.md#platform-availability).

## Installation

Add `https://github.com/modern-swift-dev/lockbox-swift.git` as a Swift Package dependency in Xcode, then add the `Lockbox` product to your target.

For a package manifest, add the dependency and product:

```swift
dependencies: [
    .package(
        url: "https://github.com/modern-swift-dev/lockbox-swift.git",
        branch: "main"
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

`set(string:)` and `set(data:)` create the item if needed and update an existing match. Missing items return `nil` when read.

## Documentation

- [Documentation overview](docs/README.md)
- [Generic passwords](docs/generic-passwords.md)
- [Internet passwords](docs/internet-passwords.md)
- [Typed keychain queries](docs/keychain-criteria.md)
- [Local and biometric authentication](docs/authentication.md)

These guides explain Lockbox's API and link to Apple for platform behavior, entitlements, and security concepts.

## License

Lockbox is available under the MIT License. See [LICENSE](LICENSE).
