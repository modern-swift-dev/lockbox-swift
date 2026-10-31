#if canImport(Security) && (os(iOS) || os(macOS))
    import Foundation
    import LocalAuthentication

    /// What an attribute-only query found for the credentials item.
    enum StoredBiometricItem: Equatable, Sendable {
        /// No item is stored.
        case missing

        /// An item is stored with the biometric state recorded when it was saved, or `nil`
        /// when it has none, such as an item saved by Lockbox 2.
        case stored(biometricState: Data?)

        /// An item is stored, but its attributes can't be read without user interaction,
        /// for example while the device is locked.
        case locked
    }

    /// The storage operations used by biometric credential flows.
    protocol BiometricCredentialStore: Sendable {
        /// Finds the item and its recorded biometric state without authenticating.
        func storedItem() -> StoredBiometricItem

        func getData() throws -> Data?

        /// Adds a new item that records `biometricState` with the data.
        ///
        /// Fails if an item already exists, so call ``remove()`` first.
        func add(data: Data, biometricState: Data) throws

        /// Deletes the item. Deleting needs no authentication, even for an item that a
        /// biometric change has invalidated.
        func remove() throws
    }

    /// Stores biometric credentials in a generic-password keychain item.
    ///
    /// The biometric state at save time is stored in the item's `kSecAttrGeneric`
    /// attribute. It isn't secret, and attribute-only queries can read it without
    /// authenticating, so a biometric change can be detected before prompting.
    struct KeychainBiometricCredentialStore: BiometricCredentialStore {
        let password: KeychainPassword
        let service: String
        let account: String
        let accessGroup: String?

        /// Attribute-only queries use a separate context so cached prompt settings cannot enable UI.
        var attributeQuery: [String: Any] {
            let context = LAContext()
            context.interactionNotAllowed = true
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: false,
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

        func storedItem() -> StoredBiometricItem {
            var result: AnyObject?
            let status = SecItemCopyMatching(attributeQuery as CFDictionary, &result)
            return Self.storedItem(status: status, attributes: result as? [String: Any])
        }

        /// Interprets an existence query's result. Other keychain errors count as no item.
        static func storedItem(status: OSStatus, attributes: [String: Any]?) -> StoredBiometricItem {
            switch status {
                case errSecSuccess:
                    .stored(biometricState: attributes?[kSecAttrGeneric as String] as? Data)
                case errSecInteractionNotAllowed:
                    .locked
                default:
                    .missing
            }
        }

        func getData() throws -> Data? {
            try password.getData()
        }

        func add(data: Data, biometricState: Data) throws {
            let status = SecItemAdd(addQuery(data: data, biometricState: biometricState) as CFDictionary, nil)
            if !status.isSuccessful {
                throw KeychainError(status: status)
            }
        }

        /// The item's create query, plus its data and recorded biometric state.
        func addQuery(data: Data, biometricState: Data) -> [String: Any] {
            var query = (password.createCriteria + [.data(data)]).query as? [String: Any] ?? [:]
            query[kSecAttrGeneric as String] = biometricState
            return query
        }

        func remove() throws {
            try password.remove()
        }
    }
#endif
