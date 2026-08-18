#if canImport(Security)
import Foundation

public extension KeychainCriterion {

    /// Availability policies for Keychain item data (`kSecAttrAccessible`).
    ///
    /// Choose a policy appropriate for when the item must be available and
    /// whether it may migrate to another device. These policies are enforced by
    /// the operating system.
    enum Accessibility: Sendable {

        /// Makes data available only while the device is unlocked.
        case whenUnlocked

        /// Makes data available only while unlocked and prevents migration to a
        /// different device.
        case whenUnlockedThisDeviceOnly

        /// Makes data available only while unlocked and while a device passcode
        /// is configured; the item does not migrate to another device.
        case whenPasswordSetThisDeviceOnly

        /// Makes data available after the first unlock following boot, including
        /// while the device is subsequently locked.
        case afterFirstUnlock

        /// Makes data available after first unlock and prevents migration to a
        /// different device.
        case afterFirstUnlockThisDeviceOnly

        /// The Security-framework value used for this accessibility policy.
        var queryValue: AnyObject {
            switch self {
                case .afterFirstUnlock:
                    kSecAttrAccessibleAfterFirstUnlock
                case .afterFirstUnlockThisDeviceOnly:
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                case .whenUnlocked:
                    kSecAttrAccessibleWhenUnlocked
                case .whenUnlockedThisDeviceOnly:
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                case .whenPasswordSetThisDeviceOnly:
                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            }
        }

        /// The criterion that applies this accessibility policy to an item.
        var criterion: KeychainCriterion {
            .accessible(self)
        }
    }
}

#endif
