# Local and biometric authentication

Lockbox provides two related APIs:

- `LocalAuthenticationService` evaluates a policy or a keychain access control on iOS and macOS.
- `BiometricService` stores and retrieves an email/password pair protected by the currently enrolled biometric set on iOS.

For authentication policies, enrollment, prompts, and device behavior, use Apple's [Local Authentication](https://developer.apple.com/documentation/localauthentication) documentation.

## Configure the app

If the app uses Face ID, provide `NSFaceIDUsageDescription` in its `Info.plist`. Apple documents this requirement and fallback behavior in [Logging a User into Your App with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/logging-a-user-into-your-app-with-face-id-or-touch-id).

## Evaluate local authentication

```swift
import LocalAuthentication
import Lockbox

let authentication = LocalAuthenticationService(
    reason: "Unlock your account",
    fallbackTitle: "Use Passcode",
    cancelTitle: "Cancel"
)

guard authentication.isProperlyConfigured(
    for: .deviceOwnerAuthentication
) else {
    // Offer the app's alternative authentication flow.
    return
}

let result = await authentication.evaluate(
    policy: .deviceOwnerAuthentication,
    reason: nil
)

switch result {
case .success:
    // Continue.
case .biometricChanged(let authenticated):
    // Decide how the app handles enrollment changes.
case .failed:
    // Keep the protected operation unavailable.
case .underlying(let error):
    // Present or log an appropriate error.
}
```

Call `invalidate()` when the context should no longer be reused. `SecurityMode.adapt(.highest)` uses `.normal` in the simulator and `.highest` on a device; pass an explicit mode when different behavior is required.

## Protect iOS credentials with biometrics

`BiometricService` uses access control based on `.biometryCurrentSet` and device-only, passcode-protected accessibility. Apple's [SecAccessControlCreateFlags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags) reference defines the platform behavior of that protection.

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
    // Use the credentials.
}

credentials.forget()
```

Check `supportedByDevice`, `isProperlyConfigured`, and `hasCredentials` to choose the appropriate UI. Handle `BiometricServiceError` cases such as `.unsupported`, `.unconfigured`, `.cancelled`, and `.lockedOut`, and keep a non-biometric recovery path for the user.
