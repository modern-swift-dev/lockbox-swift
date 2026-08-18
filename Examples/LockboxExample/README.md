# Lockbox iOS Example

This SwiftUI app demonstrates each Lockbox flow:

- Generic passwords: save, read, and delete.
- Internet passwords: save, read, and delete using a URL and account.
- Biometric credentials: save, retrieve, and forget credentials protected by Face ID or Touch ID.

## Run in Xcode

Open `LockboxExample.xcodeproj`, select the `LockboxExample` scheme, choose an iOS 18 or newer simulator or device, then run. The project references the repository-root `Lockbox` package locally, so no package URL is required.

## Biometric notes

Use a physical device with Face ID or Touch ID enrolled for the most representative biometric behavior. In Simulator, enable Face ID enrollment under **Features > Face ID > Enrolled**, then use **Features > Face ID > Matching Face** when the system prompt appears. The app includes its required `NSFaceIDUsageDescription`.

Keychain items are scoped to the example app's bundle identifier. Delete an item with the corresponding button before changing accounts or URLs if you want to reset the sample state.
