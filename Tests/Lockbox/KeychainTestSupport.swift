#if canImport(Security)
    import Foundation
    @testable import Lockbox
    import Testing

    /// Whether this test host can read and write the keychain.
    ///
    /// Test bundles without a host app can lack the keychain entitlement on some
    /// platforms and simulators, where every keychain call fails with
    /// `errSecMissingEntitlement`.
    let isKeychainAccessible: Bool = {
        let criteria: [KeychainCriterion] = [
            .securityClass(.genericPassword),
            .service("com.lockbox.tests.entitlement-check"),
            .account("probe")
        ]
        do throws(KeychainError) {
            _ = try criteria.exists()
            return true
        } catch {
            return error != .missingEntitlement
        }
    }()

    extension Trait where Self == ConditionTrait {
        /// Skips a test when the test host can't access the keychain.
        static var requiresKeychain: Self {
            .enabled(if: isKeychainAccessible, "Keychain access requires an entitlement this test host lacks")
        }
    }
#endif
