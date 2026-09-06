---
title: "Getting started | Lockbox"
description: "Install Lockbox and perform a complete generic-password workflow."
---

<a id="content"></a>

Getting started

# Store one secret end to end.

This guide uses a generic password. It is the smallest useful Lockbox workflow, and it shows how repeated saves update the same keychain item.

## Requirements

- Swift 6

- macOS 15+, iOS 18+, or visionOS 1+ for this `KeychainPassword` workflow

- tvOS 18+ and watchOS 10+ can use the lower-level `KeychainCriterion` API

- An app target with the platform capabilities it needs

## Install

Add the package in Xcode, then add its `Lockbox` product to your target. Swift Package Manager users can pin a release in their manifest.

Package.swift

```swift
dependencies: [
    .package(
        url: "https://github.com/modern-swift-dev/lockbox-swift.git",
        from: "{{version}}"
    )
],
targets: [
    .target(name: "YourTarget", dependencies: ["Lockbox"])
]
```

## Save, read, update, and remove

The service and account form the identity of a generic password. A second `set` updates that matching item. Use `remove` when the secret should no longer remain in the keychain.

Complete keychain workflow

```swift
import Foundation
import Lockbox

let password = KeychainPassword.generic(
    service: "com.example.account",
    account: "person@example.com"
)

try password.set(string: "first-secret")
let firstValue = try password.getString()

try password.set(string: "replacement-secret")
let updatedValue = try password.getString()

try password.remove()
```

### Save and update one keychain record

The service and account identify the record. A later save replaces its secret.

| Field | STORED RECORD | UPDATED RECORD |
| --- | --- | --- |
| service | com.example.app | com.example.app |
| account | ada@example.com | ada@example.com |
| secret | first-secret | replacement-secret |
