#if canImport(Security)
    #if !os(watchOS) && !os(tvOS)
        import Foundation
        import LocalAuthentication

        public extension KeychainPassword {

            /// Creates a handle for an internet-password keychain item.
            ///
            /// An internet password is identified by its URL attributes, authentication type,
            /// service, and account. HTTP URLs default to port `80`, HTTPS URLs default to port
            /// `443`, and a URL without a scheme is treated as HTTPS. Other URL schemes do not
            /// contribute protocol or port criteria. An empty URL path is stored as `/`.
            /// The returned handle does not create a keychain item until data is stored with
            /// ``set(data:)`` or ``set(string:)``.
            ///
            /// - Parameters:
            ///   - url: The URL whose scheme, host, port, and path identify the internet password.
            ///   - authenticationType: The authentication type associated with the password.
            ///   - service: An application-defined service namespace. By default, this is the
            ///     main bundle identifier.
            ///   - account: The account identifier, such as a user name or email address.
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
            /// - Returns: A handle for the internet-password item described by these attributes.
            static func internet(
                url: URL,
                authenticationType: KeychainCriterion.AuthenticationType = .default,
                // swiftlint:disable:next force_unwrapping
                service: String = Bundle.main.bundleIdentifier!,
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

                let attributes = writeAttributes(
                    accessibility: accessibility,
                    accessControl: accessControl,
                    label: label,
                    comment: comment,
                    description: description
                )

                var criteria: [KeychainCriterion] = [
                    .securityClass(.internetPassword),
                    .service(service),
                    .account(account),
                    .synchronizable(synchronizable)
                ]

                if let accessGroup {
                    criteria.append(.accessGroup(accessGroup))
                }

                if let provider = contextProvider {
                    criteria.append(.localAuthenticationContextProvider(provider))
                }

                if let scheme = url.scheme {
                    switch scheme {
                        case "http":
                            criteria.append(.urlScheme(.http))
                            if let port = url.port {
                                criteria.append(.urlPort(port))
                            } else {
                                criteria.append(.urlPort(80))
                            }
                        case "https":
                            criteria.append(.urlScheme(.https))
                            if let port = url.port {
                                criteria.append(.urlPort(port))
                            } else {
                                criteria.append(.urlPort(443))
                            }
                        default:
                            break
                    }
                } else {
                    criteria.append(.urlScheme(.https))
                    if let port = url.port {
                        criteria.append(.urlPort(port))
                    } else {
                        criteria.append(.urlPort(443))
                    }
                }

                if let host = url.host {
                    criteria.append(.urlHost(host))
                }

                if !url.path.isEmpty {
                    criteria.append(.urlPath(url.path))
                } else {
                    criteria.append(.urlPath("/"))
                }

                criteria.append(.urlAuthenticationType(authenticationType))
                return .init(criteria: criteria, attributes: attributes)
            }

            /// Returns handles for all internet-password items in a service.
            ///
            /// Returned handles preserve the stored identity attributes directly, including
            /// protocols that cannot be represented by the URL convenience API.
            ///
            /// - Parameters:
            ///   - service: The service namespace whose internet-password items to find. By
            ///     default, this is the main bundle identifier.
            ///   - accessGroup: An optional shared keychain access group used to limit the search.
            /// - Returns: Handles for the matching internet-password items.
            ///   Returns an empty array when no items match.
            /// - Throws: ``KeychainError`` when the Security framework cannot search the keychain.
            static func allInternetPassword(
                // swiftlint:disable:next force_unwrapping
                service: String = Bundle.main.bundleIdentifier!,
                accessGroup: String? = nil
            ) throws -> [KeychainPassword] {
                let accounts = try KeychainCriterion.findAll(
                    type: .internetPassword,
                    service: service,
                    accessGroup: accessGroup
                )
                return accounts.map {
                    KeychainPassword(criteria: $0.internetPasswordCriteria)
                }
            }
        }
    #endif

#endif
