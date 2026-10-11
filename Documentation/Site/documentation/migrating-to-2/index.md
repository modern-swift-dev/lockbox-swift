---
title: "Migrating to Lockbox 2 | Lockbox"
description: "Update code and stored items from Lockbox 1.x to 2.0."
---

<a id="content"></a>

Migrating to Lockbox 2

# Update a Lockbox 1.x app.

Lockbox 2 fixes keychain and biometric behavior that 1.x got wrong. Most changes are caught by the compiler. A few change runtime behavior or which stored items a handle finds.

## Source changes

| Lockbox 1.x | Lockbox 2 |
| --- | --- |
| `KeychainPassword.internet(url:service:account:)` | `KeychainPassword.internet(url:securityDomain:account:)`; internet passwords have no service |
| `allInternetPassword(service:)` | `allInternetPassword(server:securityDomain:)` |
| `internet(url:account:)` and `BiometricService(...)` defaulted `service` to the bundle identifier | Pass the service explicitly to `generic(service:account:)` and `BiometricService(service:...)` |
| `BiometricService.save(email:password:)` | `save(username:password:)` |
| `KeychainError.encodingFailed` | Removed; Lockbox never threw it |
| `KeychainError.underlyingError(status:message:)` for every status | Typed cases such as `.itemNotFound`, `.duplicateItem`, and `.interactionNotAllowed`; operations are `throws(KeychainError)` |
| `LAContext.PolicyEvaluationResult.biometricChanged` | Removed; `BiometricService` reports changes through `BiometricServiceResult.biometricChanged` |
| `LocalAuthenticationServiceProtocol.recordBiometricState()` | Replaced by the `biometricState` property |

`KeychainCriterion`, `KeychainError`, and `BiometricServiceError` have new cases, so exhaustive `switch` statements need updating.

## Behavior changes

- **`remove()` succeeds when the item doesn't exist.** `[KeychainCriterion].delete()` still throws `.itemNotFound`.
- **A biometric lockout keeps the saved credentials.** Lockbox 1.x deleted them. Call `forget()` if your app should discard them.
- **`retrieve()` throws `.noCredentials` before prompting** when nothing is stored, instead of prompting and then throwing `.unconfigured`.
- **The fallback button reports `.userFallback`** instead of `.failed`.
- **`LocalAuthenticationService.invalidate()` replaces its context.** Read `context` for each operation instead of storing it.
- **Biometric changes are tracked per saved item.** Until each item is saved again with Lockbox 2, `retrieve()` reports `.success` rather than `.biometricChanged`.
- **`BiometricService` is also available on macOS**, where it stores credentials in the data protection keychain.

## Stored internet passwords

On iOS, Lockbox 1.x couldn't save internet passwords at all, so there's nothing to migrate.

On macOS, Lockbox 2 builds a different query for some URLs, so a handle may no longer find an item saved by 1.x:

- `internet(url:...)` with an `ftp`, `ftps`, `smb`, or `ssh` URL now records the protocol.
- `internet(url:...)` with a custom scheme now records an explicit port.
- The `.url` criterion now records `http` and `https` default ports, the `/` path, and no protocol for `sftp`.

Move each affected item to its new identity once:

```swift
let url = URL(string: "ssh://files.example.com")!
let handle = KeychainPassword.internet(url: url, account: "person@example.com")

if try handle.getData() == nil {
    for old in try KeychainPassword.allInternetPassword(server: "files.example.com") {
        let query = old.criteria.query as NSDictionary
        guard query[kSecAttrAccount as String] as? String == "person@example.com",
              let secret = try old.getData() else { continue }
        try handle.set(data: secret)
        try old.remove()
    }
}
```
