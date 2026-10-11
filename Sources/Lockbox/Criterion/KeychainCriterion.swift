#if canImport(Security)
    import Foundation
    #if canImport(LocalAuthentication)
        import LocalAuthentication
    #endif

    /// A type-safe attribute used to build a Keychain Services query.
    ///
    /// Combine criteria in an array, then use its operation helpers to create,
    /// update, retrieve, or delete matching items. The resulting query follows the
    /// constraints of the Security framework; provide the attributes required by
    /// the selected ``KeychainCriterion/SecurityClass``.
    ///
    /// Example:
    /// ```swift
    /// let criteria: [KeychainCriterion] = [
    ///     .securityClass(.genericPassword),
    ///     .service("com.myapp"),
    ///     .account("user@example.com"),
    ///     .accessible(.whenUnlockedThisDeviceOnly)
    /// ]
    /// try criteria.create(data: myData)
    /// ```
    public enum KeychainCriterion: Sendable {

        /// Restricts the query to an item class (`kSecClass`).
        case securityClass(SecurityClass)

        /// Matches the service attribute (`kSecAttrService`).
        case service(String)

        /// Matches an internet-password security domain (`kSecAttrSecurityDomain`).
        case securityDomain(String)

        /// Matches the synchronizability attribute (`kSecAttrSynchronizable`).
        ///
        /// Pass `nil` to omit this attribute from the query.
        case synchronizable(Bool?)

        /// Matches both synchronizable and device-only items
        /// (`kSecAttrSynchronizableAny`).
        ///
        /// Use this case only in search, update, and delete queries. Keychain Services
        /// rejects it when creating an item.
        case synchronizableAny

        /// Matches the account attribute (`kSecAttrAccount`).
        case account(String)

        #if !os(tvOS)
            #if canImport(LocalAuthentication)
                /// Supplies the authentication context used to authorize the operation
                /// (`kSecUseAuthenticationContext`).
                case localAuthenticationContext(LAContext)

                /// Supplies a fresh authentication context when the query is built
                /// (`kSecUseAuthenticationContext`).
                ///
                /// Use this case when an `LAContext` must not be reused across operations.
                case localAuthenticationContextProvider(@Sendable () -> LAContext)
            #endif
        #endif

        /// Uses the data protection keychain on macOS (`kSecUseDataProtectionKeychain`).
        ///
        /// Without this criterion, macOS uses the file-based login keychain, which
        /// ignores accessibility and access control. The data protection keychain
        /// requires a signed app with a keychain access group. Other platforms always
        /// use it.
        case useDataProtectionKeychain

        /// Matches an access group (`kSecAttrAccessGroup`).
        ///
        /// The app must have the entitlement for the supplied group.
        case accessGroup(String)

        /// Sets the access-control policy for an item (`kSecAttrAccessControl`).
        case accessControl(SecAccessControl)

        /// Limits a matching query to one item (`kSecMatchLimitOne`).
        case limitOne

        /// Requests all matching items (`kSecMatchLimitAll`).
        case limitAll

        /// Controls whether the result includes item attributes (`kSecReturnAttributes`).
        case returnAttributes(Bool)

        /// Controls whether the result includes secret data (`kSecReturnData`).
        case returnData(Bool)

        /// Sets internet-password attributes from a URL and its authentication type.
        ///
        /// - The `http`, `https`, `ftp`, `ftps`, `smb`, and `ssh` schemes set the
        ///   protocol. Other schemes, including `sftp`, don't set a protocol.
        /// - A URL without a scheme is treated as `https`.
        /// - An explicit port is always copied. Otherwise `http` uses port `80` and
        ///   `https` uses port `443`; other schemes don't set a port.
        /// - The host is copied when present.
        /// - An empty path is stored as `/`.
        ///
        /// ``KeychainPassword/internet(url:authenticationType:service:account:accessGroup:synchronizable:useDataProtectionKeychain:accessibility:accessControl:label:comment:description:contextProvider:)``
        /// uses the same mapping.
        case url(URL, AuthenticationType = .htmlForm)

        /// Matches an internet protocol (`kSecAttrProtocol`).
        case urlScheme(InternetProtocol)

        /// Matches an internet-password server host (`kSecAttrServer`).
        case urlHost(String)

        /// Matches an internet-password server port (`kSecAttrPort`).
        case urlPort(Int)

        /// Matches an internet-password path (`kSecAttrPath`).
        case urlPath(String)

        /// Matches an internet-password authentication type (`kSecAttrAuthenticationType`).
        case urlAuthenticationType(AuthenticationType)

        /// Sets the secret data value (`kSecValueData`).
        case data(Data)

        /// Sets the item comment (`kSecAttrComment`).
        case comment(String)

        /// Sets the item description (`kSecAttrDescription`).
        case description(String)

        /// Sets the item label (`kSecAttrLabel`).
        case label(String)

        /// Sets the item's accessibility policy (`kSecAttrAccessible`).
        case accessible(Accessibility)

    }

    public extension KeychainCriterion {

        /// Returns records for all matching items in a service and optional access group.
        ///
        /// Returned records contain attributes but not secret data. Both synchronizable
        /// and device-only items are returned. If no item matches, this method returns
        /// an empty array.
        ///
        /// - Parameters:
        ///   - type: The Security item class to search. Defaults to generic passwords.
        ///   - service: The service attribute to match.
        ///   - accessGroup: An optional entitled access group to match.
        ///   - accessibility: An optional accessibility policy to match.
        ///   - useDataProtectionKeychain: Whether macOS searches the data protection keychain.
        /// - Returns: Attribute-only records for all matching items.
        /// - Throws: ``KeychainError`` when the
        ///   Security framework cannot perform the query.
        static func findAll(
            type: KeychainCriterion.SecurityClass = .genericPassword,
            service: String,
            accessGroup: String?,
            accessibility: Accessibility? = nil,
            useDataProtectionKeychain: Bool = false
        ) throws -> [KeychainRecord] {
            var criteria = findAllCriteria(
                type: type,
                service: service,
                accessGroup: accessGroup,
                accessibility: accessibility
            )
            if useDataProtectionKeychain {
                criteria.append(.useDataProtectionKeychain)
            }

            // Fetch matching items from the keychain.
            var queryResult: AnyObject?
            let status = withUnsafeMutablePointer(to: &queryResult) {
                SecItemCopyMatching(criteria.query, UnsafeMutablePointer($0))
            }

            if status.isNotFound {
                return []
            }

            if !status.isSuccessful {
                throw KeychainError(status: status)
            }

            // Cast the query result to an array of dictionaries.
            guard let resultData = queryResult as? [[String: AnyObject]] else {
                return []
            }

            // All account for this service / access group
            return resultData.compactMap { KeychainRecord($0) }
        }
    }

    extension KeychainCriterion {
        /// The query used by ``findAll(type:service:accessGroup:accessibility:useDataProtectionKeychain:)``.
        static func findAllCriteria(
            type: SecurityClass,
            service: String,
            accessGroup: String?,
            accessibility: Accessibility?
        ) -> [KeychainCriterion] {
            var criteria: [KeychainCriterion] = [
                .securityClass(type),
                .service(service),
                .synchronizableAny,
                .limitAll,
                .returnAttributes(true),
                .returnData(false)
            ]

            if let accessibility {
                criteria.append(.accessible(accessibility))
            }

            if let accessGroup {
                criteria.append(.accessGroup(accessGroup))
            }

            return criteria
        }
    }

    public extension [KeychainCriterion] {

        /// The Core Foundation dictionary represented by these criteria.
        ///
        /// If multiple criteria set the same Security attribute, the later criterion
        /// in the array wins.
        var query: CFDictionary {
            var query = [String: AnyObject]()
            for item in self {
                item.apply(to: &query)
            }
            return query as CFDictionary
        }

        /// Creates a Keychain item from these criteria and the supplied secret data.
        ///
        /// - Parameter data: The bytes stored as `kSecValueData`.
        /// - Throws: ``KeychainError`` if creation
        ///   fails, including when an equivalent item already exists.
        func create(data: Data) throws {
            var createQuery: [KeychainCriterion] = []
            createQuery.append(contentsOf: self)
            createQuery.append(.data(data))
            let status = SecItemAdd(createQuery.query, nil)
            if !status.isSuccessful {
                throw KeychainError(status: status)
            }
        }

        /// Updates the secret data and optional metadata of matching Keychain items.
        ///
        /// - Parameters:
        ///   - data: Replacement bytes stored as `kSecValueData`.
        ///   - description: An optional replacement item description.
        ///   - comment: An optional replacement item comment.
        ///   - label: An optional replacement item label.
        /// - Throws: ``KeychainError`` if the
        ///   Security framework cannot update the matching item or items.
        func update(
            data: Data,
            description: String? = nil,
            comment: String? = nil,
            label: String? = nil
        ) throws {
            var attributesToUpdate: [KeychainCriterion] = [.data(data)]

            if let description {
                attributesToUpdate.append(.description(description))
            }

            if let comment {
                attributesToUpdate.append(.comment(comment))
            }

            if let label {
                attributesToUpdate.append(.label(label))
            }

            try update(attributes: attributesToUpdate)
        }

        /// Replaces the given attributes on every item matching these criteria.
        internal func update(attributes: [KeychainCriterion]) throws {
            let status = SecItemUpdate(query, attributes.query)
            if !status.isSuccessful {
                throw KeychainError(status: status)
            }
        }

        /// Deletes every Keychain item matching these criteria.
        ///
        /// - Throws: ``KeychainError`` if no matching
        ///   item exists or the Security framework cannot delete it.
        func delete() throws {
            let status = SecItemDelete(query)
            if !status.isSuccessful {
                throw KeychainError(status: status)
            }
        }

        /// Creates an item when no item matches; otherwise updates matching items.
        ///
        /// Attempts to add the item, then updates it if an equivalent item already exists.
        /// Concurrent writers can create the same item without a duplicate-item error.
        /// A concurrent deletion between the add and update can still cause an error.
        /// - Parameter data: The bytes to create or use as replacement data.
        /// - Throws: ``KeychainError`` if the create
        ///   or update operation fails.
        func createOrUpdate(data: Data) throws {
            try Self.upsert(
                create: { try create(data: data) },
                update: { try update(data: data) }
            )
        }

        /// Keeps duplicate-item recovery independently testable without Keychain entitlements.
        internal static func upsert(create: () throws -> Void, update: () throws -> Void) throws {
            do {
                try create()
            } catch KeychainError.duplicateItem {
                try update()
            }
        }

        /// Reports whether at least one Keychain item matches these criteria.
        ///
        /// - Returns: `true` when an item is found; otherwise, `false`.
        /// - Throws: ``KeychainError`` when the
        ///   Security framework cannot perform the lookup.
        func exists() throws -> Bool {
            // Build a query to find the item that matches the service, account and
            // access group
            var items = [KeychainCriterion]()
            items.append(contentsOf: self)
            items.append(.limitOne)
            items.append(.returnAttributes(true))
            items.append(.returnData(false))

            // Try to fetch the existing keychain item that matches the query.
            var queryResult: AnyObject?
            let status = withUnsafeMutablePointer(to: &queryResult) {
                SecItemCopyMatching(items.query, UnsafeMutablePointer($0))
            }

            if status.isNotFound {
                return false
            }

            if !status.isSuccessful {
                throw KeychainError(status: status)
            }

            return true
        }

        /// Retrieves the first Keychain item matching these criteria.
        ///
        /// The returned record requests both attributes and secret data. Use criteria
        /// specific enough to identify the intended item.
        /// - Returns: The matching record, or `nil` when no item matches or the result
        ///   cannot be represented as item attributes.
        /// - Throws: ``KeychainError`` when the
        ///   Security framework cannot perform the lookup.
        func retrieve() throws -> KeychainRecord? {

            // Build a query to find the item that matches the service, account and
            // access group
            var items = [KeychainCriterion]()
            items.append(contentsOf: self)
            items.append(.limitOne)
            items.append(.returnAttributes(true))
            items.append(.returnData(true))

            // Try to fetch the existing keychain item that matches the query.
            var queryResult: AnyObject?
            let status = withUnsafeMutablePointer(to: &queryResult) {
                SecItemCopyMatching(items.query, UnsafeMutablePointer($0))
            }

            if status.isNotFound {
                return nil
            }

            if !status.isSuccessful {
                throw KeychainError(status: status)
            }

            guard let existingItem = queryResult as? [String: AnyObject] else {
                return nil
            }

            return KeychainRecord(existingItem)
        }

    }

    extension KeychainCriterion {

        /// Writes this criterion's Security attribute into a query dictionary.
        func apply(to query: inout [String: AnyObject]) {
            switch self {
                case let .securityClass(value):
                    query[kSecClass as String] = value.queryValue as AnyObject?
                case let .service(value):
                    query[kSecAttrService as String] = value as AnyObject?
                case let .securityDomain(value):
                    query[kSecAttrSecurityDomain as String] = value as AnyObject?
                case let .synchronizable(value):
                    if let value {
                        query[kSecAttrSynchronizable as String] = value ? kCFBooleanTrue : kCFBooleanFalse
                    }
                case .synchronizableAny:
                    query[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
                case let .account(value):
                    query[kSecAttrAccount as String] = value as AnyObject?
                case .useDataProtectionKeychain:
                    query[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue
                case let .accessGroup(value):
                    query[kSecAttrAccessGroup as String] = value as AnyObject?
                case .limitOne:
                    query[kSecMatchLimit as String] = kSecMatchLimitOne
                case .limitAll:
                    query[kSecMatchLimit as String] = kSecMatchLimitAll
                case let .returnAttributes(value):
                    query[kSecReturnAttributes as String] = value ? kCFBooleanTrue : kCFBooleanFalse
                case let .returnData(value):
                    query[kSecReturnData as String] = value ? kCFBooleanTrue : kCFBooleanFalse
                case let .accessControl(value):
                    query[kSecAttrAccessControl as String] = value as AnyObject?
                case let .data(value):
                    query[kSecValueData as String] = value as AnyObject?
                case let .description(value):
                    query[kSecAttrDescription as String] = value as AnyObject?
                case let .label(value):
                    query[kSecAttrLabel as String] = value as AnyObject?
                case let .comment(value):
                    query[kSecAttrComment as String] = value as AnyObject?
                case let .urlAuthenticationType(value):
                    query[kSecAttrAuthenticationType as String] = value.queryValue as AnyObject?
                case let .accessible(value):
                    query[kSecAttrAccessible as String] = value.queryValue
                case let .urlHost(value):
                    query[kSecAttrServer as String] = value as AnyObject?
                case let .urlScheme(value):
                    query[kSecAttrProtocol as String] = value.queryValue as AnyObject?
                case let .urlPort(value):
                    query[kSecAttrPort as String] = NSNumber(value: value) as AnyObject?
                case let .urlPath(value):
                    query[kSecAttrPath as String] = value as AnyObject?
                case let .url(url, type):
                    for criterion in Self.urlCriteria(url, authenticationType: type) {
                        criterion.apply(to: &query)
                    }
                    #if !os(tvOS)
                        #if canImport(LocalAuthentication)
                            case let .localAuthenticationContext(value):
                                query[kSecUseAuthenticationContext as String] = value as AnyObject?
                            case let .localAuthenticationContextProvider(callback):
                                query[kSecUseAuthenticationContext as String] = callback() as AnyObject?
                        #endif
                    #endif
            }
        }

        /// The internet-password criteria that represent a URL.
        ///
        /// See ``KeychainCriterion/url(_:_:)`` for the mapping rules.
        static func urlCriteria(_ url: URL, authenticationType: AuthenticationType) -> [KeychainCriterion] {
            var criteria: [KeychainCriterion] = []
            let internetProtocol: InternetProtocol? = if let scheme = url.scheme {
                InternetProtocol(urlScheme: scheme)
            } else {
                .https
            }

            if let internetProtocol {
                criteria.append(.urlScheme(internetProtocol))
            }

            if let port = url.port ?? internetProtocol?.defaultPort {
                criteria.append(.urlPort(port))
            }

            if let host = url.host {
                criteria.append(.urlHost(host))
            }

            criteria.append(.urlPath(url.path.isEmpty ? "/" : url.path))
            criteria.append(.urlAuthenticationType(authenticationType))
            return criteria
        }
    }

#endif
