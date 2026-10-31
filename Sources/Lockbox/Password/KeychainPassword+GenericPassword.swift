#if canImport(Security)
    import Foundation
    #if canImport(LocalAuthentication)
        import LocalAuthentication
    #endif

    public extension KeychainPassword {

        #if canImport(LocalAuthentication) && !os(tvOS)
            /// Creates a handle for a generic-password keychain item.
            ///
            /// A generic password is identified by its service and account. The returned
            /// handle does not create a keychain item until data is stored with ``set(data:)``
            /// or ``set(string:)``.
            ///
            /// - Parameters:
            ///   - service: The namespace that identifies the password, typically a reverse-DNS
            ///     identifier owned by the app or service.
            ///   - account: The account identifier within `service`, such as a user name or email address.
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
            /// - Returns: A handle for the generic-password item described by these attributes.
            static func generic(
                service: String,
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
                makeGeneric(
                    service: service,
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
            /// Creates a handle for a generic-password keychain item.
            ///
            /// A generic password is identified by its service and account. The returned
            /// handle does not create a keychain item until data is stored with ``set(data:)``
            /// or ``set(string:)``.
            ///
            /// - Parameters:
            ///   - service: The namespace that identifies the password, typically a reverse-DNS
            ///     identifier owned by the app or service.
            ///   - account: The account identifier within `service`, such as a user name or email address.
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
            /// - Returns: A handle for the generic-password item described by these attributes.
            static func generic(
                service: String,
                account: String,
                accessGroup: String? = nil,
                synchronizable: Bool? = nil,
                useDataProtectionKeychain: Bool = false,
                protection: Protection? = nil,
                label: String? = nil,
                comment: String? = nil,
                description: String? = nil
            ) -> KeychainPassword {
                makeGeneric(
                    service: service,
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

        /// Returns handles for all generic-password items in a service.
        ///
        /// The search includes synchronizable and device-only items. The returned handles
        /// preserve each matching item's account, synchronizability, and own access group,
        /// so each handle targets exactly one item even when the same account exists in
        /// several access groups. If the keychain doesn't report an item's access group,
        /// its handle has no access group. Use the handles to retrieve, update, or delete
        /// individual items.
        ///
        /// - Parameters:
        ///   - service: The service namespace whose generic-password items to find.
        ///   - accessGroup: An optional shared keychain access group used to limit the search.
        ///   - useDataProtectionKeychain: Whether macOS searches the data protection keychain.
        ///     The returned handles use the same keychain.
        /// - Returns: Handles for every matching generic-password item. Returns an empty
        ///   array when no items match.
        /// - Throws: ``KeychainError`` when the Security framework cannot search the keychain.
        static func allGenericPassword(
            service: String,
            accessGroup: String? = nil,
            useDataProtectionKeychain: Bool = false
        ) throws(KeychainError) -> [KeychainPassword] {
            let records = try KeychainCriterion.findAll(
                type: .genericPassword,
                service: service,
                accessGroup: accessGroup,
                useDataProtectionKeychain: useDataProtectionKeychain
            )
            return genericPasswords(
                from: records,
                service: service,
                useDataProtectionKeychain: useDataProtectionKeychain
            )
        }
    }

    extension KeychainPassword {
        /// Builds handles that keep each record's account, synchronizability, and access group.
        static func genericPasswords(
            from records: [KeychainRecord],
            service: String,
            useDataProtectionKeychain: Bool
        ) -> [KeychainPassword] {
            records.map {
                makeGeneric(
                    service: service,
                    account: $0.account,
                    accessGroup: $0.accessGroup,
                    synchronizable: $0.synchronizable,
                    attributes: [],
                    options: options(useDataProtectionKeychain: useDataProtectionKeychain, contextProvider: nil)
                )
            }
        }

        static func makeGeneric(
            service: String,
            account: String,
            accessGroup: String?,
            synchronizable: Bool?,
            attributes: [KeychainCriterion],
            options: [KeychainCriterion]
        ) -> KeychainPassword {

            var criteria: [KeychainCriterion] = [
                .securityClass(.genericPassword),
                .service(service),
                .account(account),
                .synchronizable(synchronizable)
            ]

            if let accessGroup {
                criteria.append(.accessGroup(accessGroup))
            }

            criteria.append(contentsOf: options)

            return .init(criteria: criteria, attributes: attributes)
        }
    }

#endif
