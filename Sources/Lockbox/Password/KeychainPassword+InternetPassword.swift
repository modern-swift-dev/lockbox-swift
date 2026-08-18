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
    ///   - accessControl: Optional Security access-control policy, such as one requiring
    ///     user presence or biometrics.
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
        accessControl: SecAccessControl? = nil,
        contextProvider: LAContextProvider? = nil
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

        if let control = accessControl {
            criteria.append(.accessControl(control))
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
        return .init(criteria: criteria)
    }

    /// Returns handles for all internet-password items in a service.
    ///
    /// Items without a URL representation are omitted because an internet-password
    /// handle requires a URL. Returned handles preserve each item's URL, account,
    /// authentication type, and the supplied access group.
    ///
    /// - Parameters:
    ///   - service: The service namespace whose internet-password items to find. By
    ///     default, this is the main bundle identifier.
    ///   - accessGroup: An optional shared keychain access group used to limit the search.
    /// - Returns: Handles for the matching internet-password items that have URLs.
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
        return accounts.compactMap {
            guard let url = $0.url else {
                return nil
            }
            return KeychainPassword.internet(
                url: url,
                authenticationType: $0.authenticationType ?? .default,
                service: service,
                account: $0.account,
                accessGroup: accessGroup
            )
        }
    }
}
#endif

#endif
