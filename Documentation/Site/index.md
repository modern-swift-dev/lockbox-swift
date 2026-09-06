---
title: "Lockbox | Typed Swift keychain access"
description: "A small, type-safe Swift wrapper around Apple Keychain Services and Local Authentication."
---

<a id="content"></a>

Swift keychain access

# Put keychain calls behind Swift types.

Lockbox stores generic and internet passwords, builds typed keychain queries, and helps iOS apps protect credentials with the enrolled biometric set.

[Get started](/docs/lockbox-swift/documentation/getting-started/) [Browse examples](/docs/lockbox-swift/examples/)

## Latest release

{{version}}

Published {{releaseDate}}. Install version `{{version}}`.

[Read release notes]({{releaseURL}})

One familiar workflow

## Save, read, update, then remove.

A `KeychainPassword` value identifies an item. `set` creates it or updates the existing match. Reads return `nil` when there is no item.

A generic password

```swift
import Lockbox

let password = KeychainPassword.generic(
    service: "com.example.account",
    account: "person@example.com"
)

try password.set(string: "a-secret")
let savedPassword = try password.getString()
try password.remove()
```

### Save and update one keychain record

The service and account identify the record. A later save replaces its secret.

| Field | STORED RECORD | UPDATED RECORD |
| --- | --- | --- |
| service | com.example.app | com.example.app |
| account | ada@example.com | ada@example.com |
| secret | first-secret | replacement-secret |

What is included

## The parts of Keychain Services that apps use every day.

### [Generic passwords](/docs/lockbox-swift/documentation/getting-started/)

Store strings or data using a service and account.

### [Internet passwords](/docs/lockbox-swift/examples/)

Associate a credential with a URL and its authentication type.

### [Typed queries](/docs/lockbox-swift/documentation/)

Build create, update, find, and delete operations from enum values.

### [Biometrics](/docs/lockbox-swift/examples/)

Save iOS credentials protected by the current biometric enrollment.

Platform support

## Built for current Apple platforms.

- **iOS 18+**
Passwords, typed queries, Local Authentication, and biometrics

- **macOS 15+**
Passwords, typed queries, and Local Authentication

- **visionOS 1+**
Passwords and typed queries

- **tvOS 18+ and watchOS 10+**
Typed Security framework queries

Open source

## Read the source before you store a secret.

Lockbox is an MIT-licensed Swift package maintained by modern-swift-dev. Its source, tests, and example app live in the repository.

[View on GitHub](https://github.com/modern-swift-dev/lockbox-swift)
