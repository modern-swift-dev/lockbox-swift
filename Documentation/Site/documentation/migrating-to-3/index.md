---
title: "Migrating to Lockbox 3 | Lockbox"
description: "Update code and stored items from Lockbox 2.x to 3.0."
---

<a id="content"></a>

Migrating to Lockbox 3

# Update a Lockbox 2.x app.

Lockbox 3 makes biometric credentials prompt on every use, makes them survive a change to the enrolled biometrics, and fixes several API and keychain-identity problems found in review. Most changes are caught by the compiler. A few change runtime behavior or which stored items a handle finds.

Lockbox 3 requires Swift 6.3.

## Source changes

| Lockbox 2.x | Lockbox 3 |
| --- | --- |
| `generic(...)` and `internet(...)` took `accessibility:` and `accessControl:` | Pass one `protection:`, either `.accessibility(...)` or `.accessControl(...)`. Keychain Services rejects an item that sets both |
| `BiometricService(service:account:group:synchronizable:localAuthenticationService:)` | `BiometricService(service:account:accessGroup:localAuthenticationService:)`. Biometric credentials are always device-only |
| `BiometricServiceError.synchronizationUnsupported` | Removed |
| `retrieve()` returned a `BiometricServiceResult` | Returns `BiometricService.Credentials`. `BiometricServiceResult` is removed |
| `BiometricServiceResult.biometricChanged(username:password:)` | `retrieve()` throws `BiometricServiceError.biometricChanged`; the credentials can no longer be read |
| `hasCredentials` | `await hasCredentials` |
| `forget()` | `await forget()` |
| `evaluate(policy:operation:reason:)` on `LAContext`, `LocalAuthenticationService`, and `LocalAuthenticationServiceProtocol` | `evaluate(policy:reason:)`. The operation was never used. Access-control evaluation keeps its `operation` |
| `KeychainRecord.description` | `KeychainRecord.itemDescription` |
| `getString()` returned `nil` when the stored bytes weren't valid UTF-8 | Throws `KeychainError.invalidUTF8`. It returns `nil` only when no item exists |
| The `.url(_:_:)` criterion defaulted to `.htmlForm` | Defaults to `.default`, like `internet(url:...)`. See [Stored internet passwords](#stored-internet-passwords) |

`KeychainError` and `BiometricServiceError` have new cases, so exhaustive `switch` statements need updating.

If you wrote your own `BiometricServiceProtocol` conformance, such as a test double, make `hasCredentials` `get async` and `forget()` `async`, and return `BiometricService.Credentials` from `retrieve()`. `Credentials` now has a public initializer for this.

Handle a biometric change with `catch` instead of a result case:

```swift
// Lockbox 2
switch try await credentials.retrieve() {
case let .success(username, password):
    signIn(username, password)
case let .biometricChanged(username, password):
    confirmIdentity(username, password)
}

// Lockbox 3
do {
    let saved = try await credentials.retrieve()
    signIn(saved.username, saved.password)
} catch BiometricServiceError.biometricChanged {
    // Sign the user in another way, then call save(username:password:).
}
```

## Behavior changes

- **`KeychainError` equality compares the status only.** `.underlyingError(status:message:)` values with the same status are equal whatever their message. `.invalidUTF8` has the status `errSecDecode`, so it equals `.underlyingError(status: errSecDecode, ...)`; match it with `catch .invalidUTF8` to tell them apart.
- **Saving with a new access control changes it.** Lockbox 2 applied an access-control policy only when it created an item, so a later save kept the old one. Lockbox 3 sends it on every save.
- **`allGenericPassword` handles target one item each.** Each handle is scoped to the access group the keychain reports for its item, instead of the group you searched with. Calling `remove()` on one handle no longer deletes items with the same account in your other access groups. An item that reports no access group gets a handle with none.
- **`.synchronizable(nil)` clears an earlier value.** In one criteria array the later criterion wins, as documented, so `.synchronizable(nil)` now removes a synchronizability set before it.
- **`BiometricService` keeps keychain work off the main actor**, including `hasCredentials` and `forget()`.
- **`biometricState` reads the enrolled-biometrics hash only.** The default `LocalAuthenticationServiceProtocol.biometricState` now returns `domainState.biometry.stateHash`, so pairing or unpairing an Apple Watch no longer changes it.

## Biometric credentials

- **Every `save` and `retrieve` prompts.** Lockbox 2 reused one authenticated context, so after the first unlock later calls could succeed without a prompt. Lockbox 3 authenticates each call with a fresh context.
- **A biometric change makes the credentials unreadable.** Items stay protected by the current biometric set, so the keychain invalidates them when fingers or faces are enrolled or removed. `retrieve()` throws `BiometricServiceError.biometricChanged` before prompting, and `hasCredentials` is `false`.
- **`save` replaces any existing credentials**, including invalidated ones, without `forget()` first. It deletes the old item, then adds the new one, so if adding fails the old credentials are already gone.
- **`save` throws `.unavailable`** when the device doesn't report its biometric state.

Lockbox 3 records the biometric state on the keychain item itself. Credentials saved by Lockbox 2 have no recorded state, so Lockbox 3 treats them as changed: `hasCredentials` is `false` and `retrieve()` throws `.biometricChanged`. Each user signs in another way once, and your app saves the credentials again.

Lockbox 2 kept the biometric state in files in Application Support, which Lockbox 3 no longer reads. Remove them once:

```swift
let baselines = URL.applicationSupportDirectory
    .appending(path: "Lockbox/Biometrics", directoryHint: .isDirectory)
try? FileManager.default.removeItem(at: baselines)
```

<a id="stored-internet-passwords"></a>

## Stored internet passwords

Lockbox 3 maps some URLs to a different keychain identity, so a handle may no longer find an internet password saved by 2.x:

- **Hosts are lowercased.** Lockbox 2 stored `Example.COM` as written, so it didn't match `example.com`.
- **A URL without a scheme maps to an https host.** Foundation parses `example.com/login` as a path, so Lockbox 2 stored it with protocol https, port 443, no server, and the path `example.com/login`. For `example.com:8443/login`, Foundation reads `example.com` as the scheme, so Lockbox 2 stored no protocol, port, or server, and the path `8443/login`.
- **The `.url(_:_:)` criterion defaults to `.default`.** Items saved through `.url(url)` used `.htmlForm`. Pass `.url(url, .htmlForm)` to keep finding them, or move them.

Move each affected item to its new identity once:

```swift
/// Moves an item saved by Lockbox 2 to its Lockbox 3 identity.
func move(_ old: KeychainPassword, to new: KeychainPassword) throws {
    guard try new.getData() == nil, let secret = try old.getData() else { return }
    try new.set(data: secret)
    try old.remove()
}

// A mixed-case host: the later criterion restores the host as Lockbox 2 stored it.
let url = URL(string: "https://Example.COM/login")!
let handle = KeychainPassword.internet(url: url, account: "person@example.com")
try move(KeychainPassword(criteria: handle.criteria + [.urlHost("Example.COM")]), to: handle)

// A URL without a scheme: rebuild the identity Lockbox 2 stored.
let schemeless = KeychainPassword.internet(
    url: URL(string: "example.com/login")!,
    account: "person@example.com"
)
let lockbox2Item = KeychainPassword(criteria: [
    .securityClass(.internetPassword),
    .account("person@example.com"),
    .urlScheme(.https),
    .urlPort(443),
    .urlPath("example.com/login"),
    .urlAuthenticationType(.default)
])
try move(lockbox2Item, to: schemeless)
```

If you saved the item with an access group or the data protection keychain, add `.accessGroup(...)` or `.useDataProtectionKeychain` to the rebuilt criteria. The host example inherits them from `handle`.
