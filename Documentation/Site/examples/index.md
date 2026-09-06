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

## Internet password

Attach the credential to its URL. Lockbox turns the URL into the keychain attributes needed by an internet password item.

Internet password

```swift
import Foundation
import Lockbox

let password = KeychainPassword.internet(
    url: URL(string: "https://api.example.com/oauth/token")!,
    service: "com.example.api",
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

## Biometric credentials on iOS

Check device support and configuration in your app before showing this path. Keep a non-biometric recovery route for users who cannot authenticate with the enrolled set.

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
    email: "person@example.com",
    password: "a-secret"
)

switch try await credentials.retrieve() {
case .success(let username, let password),
     .biometricChanged(let username, let password):
    print(username, password)
}
```
