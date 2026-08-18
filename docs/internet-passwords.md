# Internet passwords

Use an internet password when the keychain item belongs to a network endpoint. Lockbox derives the protocol, host, port, and path criteria from the URL.

## Store and retrieve a credential

```swift
import Foundation
import Lockbox

let password = KeychainPassword.internet(
    url: URL(string: "https://api.example.com/login")!,
    authenticationType: .htmlForm,
    service: "com.example.networking",
    account: "person@example.com"
)

try password.set(string: "a-secret")
let savedPassword = try password.getString()
try password.remove()
```

HTTP URLs default to port 80 and HTTPS URLs default to port 443 when the URL has no explicit port. The path is also part of the match, so use the same normalized URL when reading or removing an item.

Supported authentication types are `.ntlm`, `.msn`, `.dpa`, `.rpa`, `.httpBasic`, `.httpDigest`, `.htmlForm`, and `.default`.

## List internet passwords

```swift
let passwords = try KeychainPassword.allInternetPassword(
    service: "com.example.networking"
)
```

Each returned handle includes the reconstructed URL and account in its criteria and can be read with `getString()` or `getData()`.

For the platform's internet-password attributes and storage behavior, refer to Apple's [Keychain Services](https://developer.apple.com/documentation/security/keychain-services) documentation.
