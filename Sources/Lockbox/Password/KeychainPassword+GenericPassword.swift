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
            ///   - accessibility: When the item's data is available. Applied when the item is
            ///     written. Pass `nil` to use the Security framework's default.
            ///   - accessControl: Optional Security access-control policy, such as one requiring
            ///     user presence or biometrics. Applied only when the item is created.
            ///   - label: An optional user-visible label, applied when the item is written.
            ///   - comment: An optional comment, applied when the item is written.
            ///   - description: An optional kind description, applied when the item is written.
            ///   - contextProvider: An optional factory for the Local Authentication context
            ///     supplied to Security framework queries. It is useful with `accessControl`.
            /// - Returns: A handle for the generic-password item described by these attributes.
            static func generic(
                service: String,
                account: String,
                accessGroup: String? = nil,
                synchronizable: Bool? = nil,
                accessibility: KeychainCriterion.Accessibility? = nil,
                accessControl: SecAccessControl? = nil,
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
                        accessibility: accessibility,
                        accessControl: accessControl,
                        label: label,
                        comment: comment,
                        description: description
                    ),
                    authenticationCriterion: contextProvider.map(KeychainCriterion.localAuthenticationContextProvider)
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
            ///   - accessibility: When the item's data is available. Applied when the item is
            ///     written. Pass `nil` to use the Security framework's default.
            ///   - accessControl: Optional Security access-control policy, such as one requiring
            ///     user presence or biometrics. Applied only when the item is created.
            ///   - label: An optional user-visible label, applied when the item is written.
            ///   - comment: An optional comment, applied when the item is written.
            ///   - description: An optional kind description, applied when the item is written.
            /// - Returns: A handle for the generic-password item described by these attributes.
            static func generic(
                service: String,
                account: String,
                accessGroup: String? = nil,
                synchronizable: Bool? = nil,
                accessibility: KeychainCriterion.Accessibility? = nil,
                accessControl: SecAccessControl? = nil,
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
                        accessibility: accessibility,
                        accessControl: accessControl,
                        label: label,
                        comment: comment,
                        description: description
                    ),
                    authenticationCriterion: nil
                )
            }
        #endif

        /// Returns handles for all generic-password items in a service.
        ///
        /// The returned handles preserve each matching item's account and the supplied
        /// access group. They can be used to retrieve, update, or delete individual items.
        ///
        /// - Parameters:
        ///   - service: The service namespace whose generic-password items to find.
        ///   - accessGroup: An optional shared keychain access group used to limit the search.
        /// - Returns: Handles for every matching generic-password item. Returns an empty
        ///   array when no items match.
        /// - Throws: ``KeychainError`` when the Security framework cannot search the keychain.
        static func allGenericPassword(
            service: String,
            accessGroup: String? = nil
        ) throws -> [KeychainPassword] {
            let accounts = try KeychainCriterion.findAll(
                type: .genericPassword,
                service: service,
                accessGroup: accessGroup
            )
            return accounts.map {
                KeychainPassword.generic(
                    service: service,
                    account: $0.account,
                    accessGroup: accessGroup
                )
            }
        }
    }

    extension KeychainPassword {
        static func makeGeneric(
            service: String,
            account: String,
            accessGroup: String?,
            synchronizable: Bool?,
            attributes: [KeychainCriterion],
            authenticationCriterion: KeychainCriterion?
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

            if let authenticationCriterion {
                criteria.append(authenticationCriterion)
            }

            return .init(criteria: criteria, attributes: attributes)
        }
    }

#endif
