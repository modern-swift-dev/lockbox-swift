# Typed keychain queries

`KeychainCriterion` exposes Lockbox's lower-level, type-safe query builder. Use it when the `KeychainPassword` factories do not express the attributes or operation you need.

## Create or update an item

```swift
import Foundation
import Lockbox

let criteria: [KeychainCriterion] = [
    .securityClass(.genericPassword),
    .service("com.example.account"),
    .account("person@example.com"),
    .accessible(.whenUnlockedThisDeviceOnly)
]

let data = Data("a-secret".utf8)
try criteria.createOrUpdate(data: data)
```

You can call `create(data:)` or `update(data:description:comment:label:)` when you need explicit behavior. `createOrUpdate(data:)` checks for a match first.

## Retrieve, test, and delete

```swift
if try criteria.exists(), let record = try criteria.retrieve() {
    let value = record.data.flatMap { String(data: $0, encoding: .utf8) }
    // Use record.account, record.creation, value, and other attributes.
}

try criteria.delete()
```

`retrieve()` returns `nil` when no item matches. Other Security framework failures throw `KeychainError.underlyingError`, whose `localizedDescription` includes the status and the system message when available.

## Find records

```swift
let records = try KeychainCriterion.findAll(
    type: .genericPassword,
    service: "com.example.account",
    accessGroup: nil,
    accessibility: .whenUnlockedThisDeviceOnly
)
```

`findAll` returns item attributes as `KeychainRecord` values and returns an empty array when there are no matches. It does not return secret data; retrieve a specific item when you need its data.

## Criteria

The query builder supports security class, service, account, synchronization, access group, accessibility, access control, authentication context, result limits, returned fields, URL components, internet authentication type, data, comment, description, and label.

Criteria map to Apple's Security framework attributes. Consult [Keychain Services](https://developer.apple.com/documentation/security/keychain-services) for their system meaning and constraints; Lockbox adds typed construction and operation helpers rather than redefining those rules.
