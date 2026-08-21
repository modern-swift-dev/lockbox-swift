# Lockbox

Lockbox is a small, type-safe Swift wrapper around Apple Keychain Services and Local Authentication. It stores generic and internet passwords, supports raw `Data`, builds keychain queries from Swift enum values, and provides an iOS biometric credential service.

Read the [Lockbox documentation](https://modern-swift-dev.github.io/lockbox-swift/) for guides, examples, and API reference.

## Requirements

- Swift 6
- macOS 15+, iOS 18+, tvOS 18+, watchOS 10+, or visionOS 1+

Some APIs have narrower platform availability. The [documentation hub](https://modern-swift-dev.github.io/lockbox-swift/documentation/) lists those limits.

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

See the [getting started guide](https://modern-swift-dev.github.io/lockbox-swift/documentation/getting-started/) for the complete workflow and the [examples](https://modern-swift-dev.github.io/lockbox-swift/examples/) for generic passwords, internet passwords, typed queries, and biometric credentials.

## Website releases

The generated website in `docs/` is committed to the repository. `make site-build` replaces that directory only after the Astro build, DocC build, and internal-link check pass. After publishing a GitHub release:

1. Run `make site-setup` to install the locked website dependencies.
2. Run `make site-build` to fetch the latest published release and rebuild the Astro and DocC output.
3. Run `make site-preview`, then review the release details, responsive pages, and generated API documentation at `http://localhost:8000/lockbox-swift/`.
4. Stop the preview, run `make site-validate`, review `git diff`, and commit the updated `docs/` output with the source changes.

GitHub Pages requires one manual repository setting. Under **Settings > Pages**, choose **Deploy from a branch**, select `main` and `/docs`, then save. The build does not change this setting. See GitHub's [branch publishing instructions](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).

## License

Lockbox is available under the MIT License. See [LICENSE](LICENSE).
