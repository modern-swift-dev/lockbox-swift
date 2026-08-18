# Lockbox documentation

Lockbox has a high-level password API, a lower-level typed query API, and authentication helpers.

## Guides

- [Generic passwords](generic-passwords.md): store strings or raw data under a service and account.
- [Internet passwords](internet-passwords.md): associate a credential with a URL and authentication type.
- [Typed keychain queries](keychain-criteria.md): create, update, search, and delete items with explicit criteria.
- [Local and biometric authentication](authentication.md): evaluate authentication policies and protect iOS credentials with the current biometric set.

For the operating system's storage and security model, see Apple's [Keychain Services](https://developer.apple.com/documentation/security/keychain-services) documentation. The guides here cover only Lockbox-specific usage.

## Platform availability

| API | Availability |
| --- | --- |
| `KeychainCriterion` and its operations | Platforms that provide Apple's Security framework |
| `KeychainPassword.generic` and `.internet` | iOS, macOS, and visionOS |
| `LocalAuthenticationService` | iOS and macOS |
| `BiometricService` | iOS |

The package deployment targets are macOS 15, iOS 18, tvOS 18, watchOS 10, and visionOS 1.
