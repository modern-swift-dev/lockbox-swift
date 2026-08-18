# Generic passwords

Use a generic password for a secret identified by your app's service name and an account. For background on choosing and storing keychain items, see Apple's [Using the keychain to manage user secrets](https://developer.apple.com/documentation/security/using-the-keychain-to-manage-user-secrets).

## Store, read, and remove a string

```swift
import Lockbox

let password = KeychainPassword.generic(
    service: "com.example.account",
    account: "person@example.com"
)

try password.set(string: "a-secret")

if let value = try password.getString() {
    // Use the value.
}

try password.remove()
```

Calling `set(string:)` again updates the matching item. `getString()` returns `nil` if the item does not exist or its bytes are not valid UTF-8. Keychain failures are thrown as `KeychainError`.

## Store raw data

```swift
let token = KeychainPassword.generic(
    service: "com.example.session",
    account: "current"
)

try token.set(data: tokenData)
let savedData = try token.getData()
```

Keychain storage is intended for small secrets, not general files or databases. Apple describes the intended scope in [Keychain Services](https://developer.apple.com/documentation/security/keychain-services).

## List accounts for a service

```swift
let passwords = try KeychainPassword.allGenericPassword(
    service: "com.example.account"
)

for password in passwords {
    let value = try password.getString()
    // Use value.
}
```

The returned values are `KeychainPassword` handles. Reading each handle retrieves its secret.

## Sharing and synchronization

Pass `accessGroup:` when targets are configured to share a keychain group, and pass `synchronizable: true` when the item should be eligible for iCloud Keychain synchronization:

```swift
let sharedPassword = KeychainPassword.generic(
    service: "com.example.account",
    account: "person@example.com",
    accessGroup: "TEAMID.com.example.shared",
    synchronizable: true
)
```

Lockbox does not configure signing entitlements. Follow Apple's [Configuring keychain sharing](https://developer.apple.com/documentation/xcode/configuring-keychain-sharing) and [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps) guides before supplying an access group.
