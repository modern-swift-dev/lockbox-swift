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
            /// security domain, and account. The URL is mapped like ``KeychainCriterion/url(_:_:)``.
            /// Internet passwords have no service attribute; on iOS, the app's access groups
            /// already keep its items separate from other apps' items.
            /// The returned handle does not create a keychain item until data is stored with
            /// ``set(data:)`` or ``set(string:)``.
            ///
            /// - Parameters:
            ///   - url: The URL whose scheme, host, port, and path identify the internet password.
            ///   - authenticationType: The authentication type associated with the password.
            ///   - securityDomain: An optional security domain, such as an HTTP
            ///     authentication realm (`kSecAttrSecurityDomain`).
            ///   - account: The account identifier, such as a user name or email address.
            ///   - accessGroup: An optional shared keychain access group. The calling app must
            ///     have the corresponding entitlement.
            ///   - synchronizable: Whether the item participates in iCloud Keychain syncing.
            ///     Pass `nil` to omit this attribute from the query.
            ///   - useDataProtectionKeychain: Whether macOS stores the item in the data protection
            ///     keychain, which behaves like the iOS keychain. Requires a signed app with a
            ///     keychain access group. Other platforms always use it.
            ///   - protection: How the item's data is protected: an accessibility policy, applied
            ///     whenever the item is written, or an access-control policy such as one requiring
            ///     user presence or biometrics, applied only when the item is created. An item
            ///     can't use both. Pass `nil` to use the Security framework's default.
            ///   - label: An optional user-visible label, applied when the item is written.
            ///   - comment: An optional comment, applied when the item is written.
            ///   - description: An optional kind description, applied when the item is written.
            ///   - contextProvider: An optional factory for the Local Authentication context
            ///     supplied to Security framework queries. It is useful with an access-control ``Protection``.
            /// - Returns: A handle for the internet-password item described by these attributes.
            static func internet(
                url: URL,
                authenticationType: KeychainCriterion.AuthenticationType = .default,
                securityDomain: String? = nil,
                account: String,
                accessGroup: String? = nil,
                synchronizable: Bool? = nil,
                useDataProtectionKeychain: Bool = false,
                protection: Protection? = nil,
                label: String? = nil,
                comment: String? = nil,
                description: String? = nil,
                contextProvider: LAContextProvider? = nil
            ) -> KeychainPassword {
                makeInternet(
                    url: url,
                    authenticationType: authenticationType,
                    securityDomain: securityDomain,
                    account: account,
                    accessGroup: accessGroup,
                    synchronizable: synchronizable,
                    attributes: writeAttributes(
                        protection: protection,
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
            /// security domain, and account. The URL is mapped like ``KeychainCriterion/url(_:_:)``.
            /// Internet passwords have no service attribute; on iOS, the app's access groups
            /// already keep its items separate from other apps' items.
            /// The returned handle does not create a keychain item until data is stored with
            /// ``set(data:)`` or ``set(string:)``.
            ///
            /// - Parameters:
            ///   - url: The URL whose scheme, host, port, and path identify the internet password.
            ///   - authenticationType: The authentication type associated with the password.
            ///   - securityDomain: An optional security domain, such as an HTTP
            ///     authentication realm (`kSecAttrSecurityDomain`).
            ///   - account: The account identifier, such as a user name or email address.
            ///   - accessGroup: An optional shared keychain access group. The calling app must
            ///     have the corresponding entitlement.
            ///   - synchronizable: Whether the item participates in iCloud Keychain syncing.
            ///     Pass `nil` to omit this attribute from the query.
            ///   - useDataProtectionKeychain: Whether macOS stores the item in the data protection
            ///     keychain, which behaves like the iOS keychain. Requires a signed app with a
            ///     keychain access group. Other platforms always use it.
            ///   - protection: How the item's data is protected: an accessibility policy, applied
            ///     whenever the item is written, or an access-control policy such as one requiring
            ///     user presence or biometrics, applied only when the item is created. An item
            ///     can't use both. Pass `nil` to use the Security framework's default.
            ///   - label: An optional user-visible label, applied when the item is written.
            ///   - comment: An optional comment, applied when the item is written.
            ///   - description: An optional kind description, applied when the item is written.
            /// - Returns: A handle for the internet-password item described by these attributes.
            static func internet(
                url: URL,
                authenticationType: KeychainCriterion.AuthenticationType = .default,
                securityDomain: String? = nil,
                account: String,
                accessGroup: String? = nil,
                synchronizable: Bool? = nil,
                useDataProtectionKeychain: Bool = false,
                protection: Protection? = nil,
                label: String? = nil,
                comment: String? = nil,
                description: String? = nil
            ) -> KeychainPassword {
                makeInternet(
                    url: url,
                    authenticationType: authenticationType,
                    securityDomain: securityDomain,
                    account: account,
                    accessGroup: accessGroup,
                    synchronizable: synchronizable,
                    attributes: writeAttributes(
                        protection: protection,
                        label: label,
                        comment: comment,
                        description: description
                    ),
                    options: options(useDataProtectionKeychain: useDataProtectionKeychain, contextProvider: nil)
                )
            }
        #endif

        /// Returns handles for the internet-password items the app can access.
        ///
        /// Returned handles preserve the stored identity attributes directly, including
        /// protocols that cannot be represented by the URL convenience API. On macOS, the
        /// login keychain also contains internet passwords saved by other apps, so narrow
        /// the search with `server` or `securityDomain`.
        ///
        /// - Parameters:
        ///   - server: An optional server host to match.
        ///   - securityDomain: An optional security domain to match.
        ///   - accessGroup: An optional shared keychain access group used to limit the search.
        ///   - useDataProtectionKeychain: Whether macOS searches the data protection keychain.
        ///     The returned handles use the same keychain.
        /// - Returns: Handles for the matching internet-password items.
        ///   Returns an empty array when no items match.
        /// - Throws: ``KeychainError`` when the Security framework cannot search the keychain.
        static func allInternetPassword(
            server: String? = nil,
            securityDomain: String? = nil,
            accessGroup: String? = nil,
            useDataProtectionKeychain: Bool = false
        ) throws(KeychainError) -> [KeychainPassword] {
            let criteria = internetPasswordSearchCriteria(
                server: server,
                securityDomain: securityDomain,
                accessGroup: accessGroup,
                useDataProtectionKeychain: useDataProtectionKeychain
            )
            let records = try KeychainCriterion.records(matching: criteria)
            return internetPasswords(from: records, useDataProtectionKeychain: useDataProtectionKeychain)
        }
    }

    extension KeychainPassword {
        /// The query used by ``allInternetPassword(server:securityDomain:accessGroup:useDataProtectionKeychain:)``.
        static func internetPasswordSearchCriteria(
            server: String?,
            securityDomain: String?,
            accessGroup: String?,
            useDataProtectionKeychain: Bool
        ) -> [KeychainCriterion] {
            var criteria = KeychainCriterion.findAllCriteria(
                type: .internetPassword,
                service: nil,
                accessGroup: accessGroup,
                accessibility: nil
            )
            if let server {
                criteria.append(.urlHost(server))
            }
            if let securityDomain {
                criteria.append(.securityDomain(securityDomain))
            }
            return criteria + options(useDataProtectionKeychain: useDataProtectionKeychain, contextProvider: nil)
        }

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
            securityDomain: String?,
            account: String,
            accessGroup: String?,
            synchronizable: Bool?,
            attributes: [KeychainCriterion],
            options: [KeychainCriterion]
        ) -> KeychainPassword {

            var criteria: [KeychainCriterion] = [
                .securityClass(.internetPassword),
                .account(account),
                .synchronizable(synchronizable)
            ]

            if let securityDomain {
                criteria.append(.securityDomain(securityDomain))
            }

            if let accessGroup {
                criteria.append(.accessGroup(accessGroup))
            }

            criteria.append(contentsOf: options)

            criteria.append(contentsOf: KeychainCriterion.urlCriteria(url, authenticationType: authenticationType))
            return .init(criteria: criteria, attributes: attributes)
        }
    }

#endif
