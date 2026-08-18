#if canImport(Security)
#if !os(watchOS) && !os(tvOS)
import Foundation
import LocalAuthentication

public extension KeychainPassword {

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
    ///   - accessControl: Optional Security access-control policy, such as one requiring
    ///     user presence or biometrics.
    ///   - contextProvider: An optional factory for the Local Authentication context
    ///     supplied to Security framework queries. It is useful with `accessControl`.
    /// - Returns: A handle for the generic-password item described by these attributes.
    static func generic(
        service: String,
        account: String,
        accessGroup: String? = nil,
        synchronizable: Bool? = nil,
        accessControl: SecAccessControl? = nil,
        contextProvider: LAContextProvider? = nil
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

        if let control = accessControl {
            criteria.append(.accessControl(control))
        }

        if let provider = contextProvider {
            criteria.append(.localAuthenticationContextProvider(provider))
        }

        return .init(criteria: criteria)
    }

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

#endif

#endif
