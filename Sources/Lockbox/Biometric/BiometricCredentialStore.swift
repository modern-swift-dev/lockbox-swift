#if canImport(Security) && (os(iOS) || os(macOS))
    import Foundation
    import LocalAuthentication

    /// The storage operations used by biometric credential flows.
    protocol BiometricCredentialStore: Sendable {
        /// Whether credentials are stored, determined without authenticating.
        func exists() -> Bool
        func getData() throws -> Data?
        func set(data: Data) throws
        func remove() throws
    }

    /// Stores biometric credentials in a generic-password keychain item.
    struct KeychainBiometricCredentialStore: BiometricCredentialStore {
        let password: KeychainPassword
        let service: String
        let account: String
        let accessGroup: String?
        let synchronizable: Bool

        /// Attribute-only queries use a separate context so cached prompt settings cannot enable UI.
        var existenceQuery: [String: Any] {
            let context = LAContext()
            context.interactionNotAllowed = true
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: synchronizable,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecUseAuthenticationContext as String: context,
                kSecUseDataProtectionKeychain as String: true
            ]
            if let accessGroup {
                query[kSecAttrAccessGroup as String] = accessGroup
            }
            return query
        }

        func exists() -> Bool {
            Self.indicatesStoredItem(SecItemCopyMatching(existenceQuery as CFDictionary, nil))
        }

        /// An item that needs user interaction to read still exists.
        static func indicatesStoredItem(_ status: OSStatus) -> Bool {
            status == errSecSuccess || status == errSecInteractionNotAllowed
        }

        func getData() throws -> Data? {
            try password.getData()
        }

        func set(data: Data) throws {
            try password.set(data: data)
        }

        func remove() throws {
            try password.remove()
        }
    }
#endif
