#if canImport(Security)
    import Foundation
    #if canImport(LocalAuthentication)
        import LocalAuthentication
    #endif

    public extension KeychainPassword {

        #if canImport(LocalAuthentication) && !os(tvOS)
            /// Creates a handle for an internet-password keychain item.
            ///
            /// An internet password is identified by its URL attributes, authentication type,
            /// service, and account. The URL is mapped like ``KeychainCriterion/url(_:_:)``.
            /// The returned handle does not create a keychain item until data is stored with
            /// ``set(data:)`` or ``set(string:)``.
            ///
            /// - Parameters:
            ///   - url: The URL whose scheme, host, port, and path identify the internet password.
            ///   - authenticationType: The authentication type associated with the password.
            ///   - service: An application-defined service namespace, such as the app's
            ///     bundle identifier.
            ///   - account: The account identifier, such as a user name or email address.
            ///   - accessGroup: An optional shared keychain access group. The calling app must
            ///     have the corresponding entitlement.
            ///   - synchronizable: Whether the item participates in iCloud Keychain syncing.
            ///     Pass `nil` to omit this attribute from the query.
            ///   - useDataProtectionKeychain: Whether macOS stores the item in the data protection
            ///     keychain, which behaves like the iOS keychain. Requires a signed app with a
            ///     keychain access group. Other platforms always use it.
            ///   - accessibility: When the item's data is available. Applied when the item is
            ///     written. Pass `nil` to use the Security framework's default.
            ///   - accessControl: Optional Security access-control policy, such as one requiring
            ///     user presence or biometrics. Applied only when the item is created.
            ///   - label: An optional user-visible label, applied when the item is written.
            ///   - comment: An optional comment, applied when the item is written.
            ///   - description: An optional kind description, applied when the item is written.
            ///   - contextProvider: An optional factory for the Local Authentication context
            ///     supplied to Security framework queries. It is useful with `accessControl`.
            /// - Returns: A handle for the internet-password item described by these attributes.
            static func internet(
                url: URL,
                authenticationType: KeychainCriterion.AuthenticationType = .default,
                service: String,
                account: String,
                accessGroup: String? = nil,
                synchronizable: Bool? = nil,
                useDataProtectionKeychain: Bool = false,
                accessibility: KeychainCriterion.Accessibility? = nil,
                accessControl: SecAccessControl? = nil,
                label: String? = nil,
                comment: String? = nil,
                description: String? = nil,
                contextProvider: LAContextProvider? = nil
            ) -> KeychainPassword {
                makeInternet(
                    url: url,
                    authenticationType: authenticationType,
                    service: service,
                    account: account,
                    accessGroup: accessGroup,
                    synchronizable: synchronizable,
                    attributes: writeAttributes(
                        accessibility: accessibility,
                        accessControl: accessControl,
                        label: label,
                        comment: comment,
                        description: description
                    ),
                    options: options(
                        useDataProtectionKeychain: useDataProtectionKeychain,
                        contextProvider: contextProvider.map(KeychainCriterion.localAuthenticationContextProvider)
                    )
                )
            }
        #else
            /// Creates a handle for an internet-password keychain item.
            ///
            /// An internet password is identified by its URL attributes, authentication type,
            /// service, and account. The URL is mapped like ``KeychainCriterion/url(_:_:)``.
            /// The returned handle does not create a keychain item until data is stored with
            /// ``set(data:)`` or ``set(string:)``.
            ///
            /// - Parameters:
            ///   - url: The URL whose scheme, host, port, and path identify the internet password.
            ///   - authenticationType: The authentication type associated with the password.
            ///   - service: An application-defined service namespace, such as the app's
            ///     bundle identifier.
            ///   - account: The account identifier, such as a user name or email address.
            ///   - accessGroup: An optional shared keychain access group. The calling app must
            ///     have the corresponding entitlement.
            ///   - synchronizable: Whether the item participates in iCloud Keychain syncing.
            ///     Pass `nil` to omit this attribute from the query.
            ///   - useDataProtectionKeychain: Whether macOS stores the item in the data protection
            ///     keychain, which behaves like the iOS keychain. Requires a signed app with a
            ///     keychain access group. Other platforms always use it.
            ///   - accessibility: When the item's data is available. Applied when the item is
            ///     written. Pass `nil` to use the Security framework's default.
            ///   - accessControl: Optional Security access-control policy, such as one requiring
            ///     user presence or biometrics. Applied only when the item is created.
            ///   - label: An optional user-visible label, applied when the item is written.
            ///   - comment: An optional comment, applied when the item is written.
            ///   - description: An optional kind description, applied when the item is written.
            /// - Returns: A handle for the internet-password item described by these attributes.
            static func internet(
                url: URL,
                authenticationType: KeychainCriterion.AuthenticationType = .default,
                service: String,
                account: String,
                accessGroup: String? = nil,
                synchronizable: Bool? = nil,
                useDataProtectionKeychain: Bool = false,
                accessibility: KeychainCriterion.Accessibility? = nil,
                accessControl: SecAccessControl? = nil,
                label: String? = nil,
                comment: String? = nil,
                description: String? = nil
            ) -> KeychainPassword {
                makeInternet(
                    url: url,
                    authenticationType: authenticationType,
                    service: service,
                    account: account,
                    accessGroup: accessGroup,
                    synchronizable: synchronizable,
                    attributes: writeAttributes(
                        accessibility: accessibility,
                        accessControl: accessControl,
                        label: label,
                        comment: comment,
                        description: description
                    ),
                    options: options(useDataProtectionKeychain: useDataProtectionKeychain, contextProvider: nil)
                )
            }
        #endif

        /// Returns handles for all internet-password items in a service.
        ///
        /// Returned handles preserve the stored identity attributes directly, including
        /// protocols that cannot be represented by the URL convenience API.
        ///
        /// - Parameters:
        ///   - service: The service namespace whose internet-password items to find.
        ///   - accessGroup: An optional shared keychain access group used to limit the search.
        ///   - useDataProtectionKeychain: Whether macOS searches the data protection keychain.
        ///     The returned handles use the same keychain.
        /// - Returns: Handles for the matching internet-password items.
        ///   Returns an empty array when no items match.
        /// - Throws: ``KeychainError`` when the Security framework cannot search the keychain.
        static func allInternetPassword(
            service: String,
            accessGroup: String? = nil,
            useDataProtectionKeychain: Bool = false
        ) throws(KeychainError) -> [KeychainPassword] {
            let accounts = try KeychainCriterion.findAll(
                type: .internetPassword,
                service: service,
                accessGroup: accessGroup,
                useDataProtectionKeychain: useDataProtectionKeychain
            )
            return internetPasswords(from: accounts, useDataProtectionKeychain: useDataProtectionKeychain)
        }
    }

    extension KeychainPassword {
        /// Builds handles from the stored identity attributes of each record.
        static func internetPasswords(
            from records: [KeychainRecord],
            useDataProtectionKeychain: Bool
        ) -> [KeychainPassword] {
            records.map {
                KeychainPassword(
                    criteria: $0.internetPasswordCriteria
                        + options(useDataProtectionKeychain: useDataProtectionKeychain, contextProvider: nil)
                )
            }
        }

        static func makeInternet(
            url: URL,
            authenticationType: KeychainCriterion.AuthenticationType,
            service: String,
            account: String,
            accessGroup: String?,
            synchronizable: Bool?,
            attributes: [KeychainCriterion],
            options: [KeychainCriterion]
        ) -> KeychainPassword {

            var criteria: [KeychainCriterion] = [
                .securityClass(.internetPassword),
                .service(service),
                .account(account),
                .synchronizable(synchronizable)
            ]

            if let accessGroup {
                criteria.append(.accessGroup(accessGroup))
            }

            criteria.append(contentsOf: options)

            criteria.append(contentsOf: KeychainCriterion.urlCriteria(url, authenticationType: authenticationType))
            return .init(criteria: criteria, attributes: attributes)
        }
    }

#endif
