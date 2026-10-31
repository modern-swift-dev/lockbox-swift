---
title: "Examples | Lockbox"
description: "Working Lockbox examples for passwords, criteria, and biometrics."
---

<a id="content"></a>

Examples

# Code from the package's real APIs.

These examples use the same public calls described in the repository guides and the bundled example app. Replace the service names and accounts with values owned by your app.

<a id="generic-password"></a>

## Generic password data

Use a generic password for a small secret identified by a service and account. Lockbox can store raw `Data` when the value is not a string.

Generic password

```swift
import Foundation
import Lockbox

let tokenData = Data("session-token".utf8)
let token = KeychainPassword.generic(
    service: "com.example.session",
    account: "current"
)

try token.set(data: tokenData)
let savedToken = try token.getData()
```

Pass `protection`, `label`, `comment`, or `description` to set item attributes when the item is written. These attributes don't take part in finding the item, so a later save with different values updates the same item. `protection` takes either an accessibility policy, such as `.accessibility(.afterFirstUnlockThisDeviceOnly)`, or an access-control policy, such as `.accessControl(accessControl)`. Saving with a different policy changes the item's protection. Keychain Services rejects an item that sets both.

Background-readable token

```swift
let backgroundToken = KeychainPassword.generic(
    service: "com.example.session",
    account: "background",
    protection: .accessibility(.afterFirstUnlockThisDeviceOnly),
    label: "Session token"
)
```

## Internet password

Attach the credential to its URL. Lockbox turns the URL into the keychain attributes needed by an internet password item. A URL without a scheme, such as `example.com/login` or `example.com:8443/login`, is treated as `https`, with its first component as the host. Internet passwords are identified by their URL, authentication type, account, and optional security domain; they have no service. The authentication type defaults to `.default` (`kSecAttrAuthenticationTypeDefault`) for both `KeychainPassword.internet(url:...)` and the `.url(_:)` criterion, so the same URL refers to the same item through either. To use another one, pass `authenticationType:` to `internet(url:...)` or the type as the second argument of `.url(_:_:)`.

Internet password

```swift
import Foundation
import Lockbox

let password = KeychainPassword.internet(
    url: URL(string: "https://api.example.com/oauth/token")!,
    account: "person@example.com"
)

try password.set(string: "api-secret")
```

<a id="keychain-criteria"></a>

## Typed keychain criteria

Use criteria when the password factories do not cover the attributes or operation you need. The retrieved record contains the returned attributes and data.

Keychain criterion

```swift
import Foundation
import Lockbox

let criteria: [KeychainCriterion] = [
    .securityClass(.genericPassword),
    .service("com.example.account"),
    .account("person@example.com")
]

if try criteria.exists(), let record = try criteria.retrieve() {
    let value = record.data.flatMap { String(data: $0, encoding: .utf8) }
    print(record.account, value ?? "")
}
```

<a id="biometrics"></a>

## Biometric credentials on iOS and macOS

Check device support and configuration in your app before showing this path. Keep a non-biometric recovery route for users who cannot authenticate with the enrolled set. On macOS, the credentials live in the data protection keychain, so the app must be signed with a keychain access group.

Biometric service

```swift
import Lockbox

let authentication = LocalAuthenticationService(
    reason: "Access your saved credentials"
)
let credentials = BiometricService(
    service: "com.example.credentials",
    localAuthenticationService: authentication
)

try await credentials.save(
    username: "person@example.com",
    password: "a-secret"
)

do {
    let saved = try await credentials.retrieve()
    print(saved.username, saved.password)
} catch BiometricServiceError.biometricChanged {
    // The enrolled biometrics changed, so the saved credentials can never be read.
    // Sign the user in another way, then save again. You don't need forget() first.
}
```

Every `save` and `retrieve` asks the user to authenticate. A successful call doesn't unlock the next one.

### When the enrolled biometrics change

The credentials are protected by the biometric set enrolled when they were saved. Adding or removing a fingerprint, or re-enrolling a face, makes the keychain invalidate them permanently. Lockbox records the biometric state with the credentials, so it detects this before prompting:

- `retrieve()` throws `BiometricServiceError.biometricChanged`.
- `hasCredentials` is `false`.
- `save(username:password:)` replaces the credentials.

`retrieve()` also throws `.biometricChanged` for credentials saved without a recorded state, such as by Lockbox 2, and on a device that doesn't report its biometric state. Saving again fixes the first case.

`hasCredentials` and `forget()` run their keychain work off the main actor, so both are `async`:

```swift
if await credentials.hasCredentials {
    // Offer to unlock.
}

await credentials.forget()
```
