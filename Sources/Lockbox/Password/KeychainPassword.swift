#if canImport(Security)
    import Foundation
    import Security

    /// A handle for a single generic or internet password item in the keychain.
    ///
    /// Create a handle with ``generic(service:account:accessGroup:synchronizable:useDataProtectionKeychain:accessibility:accessControl:label:comment:description:contextProvider:)``
    /// or ``internet(url:authenticationType:securityDomain:account:accessGroup:synchronizable:useDataProtectionKeychain:accessibility:accessControl:label:comment:description:contextProvider:)``,
    /// then use ``set(data:)``, ``set(string:)``, ``getData()``, ``getString()``, or
    /// ``remove()`` to operate on its matching item. A handle does not read or retain
    /// the item's secret until a retrieval method is called.
    ///
    /// Example:
    /// ```swift
    /// let password = KeychainPassword.generic(
    ///     service: "com.myapp",
    ///     account: "user@example.com"
    /// )
    /// try password.set(string: "mysecret")
    /// let value = try password.getString()
    /// ```
    public struct KeychainPassword: Sendable {

        /// The criteria used to identify this keychain item and configure its operations.
        ///
        /// The criteria include the item's keychain class and identifying attributes,
        /// such as its service and account. They do not include the item's stored data
        /// or the write-only ``attributes``.
        public let criteria: [KeychainCriterion]

        /// Attributes applied when the item is written but never used to find it.
        ///
        /// Access control is applied only when the item is created. Other attributes
        /// are applied on creation and replaced on update.
        public let attributes: [KeychainCriterion]

        /// Creates a handle from explicit keychain criteria.
        ///
        /// Use this initializer when the password factories don't express the item you
        /// need. Include the item's class and identifying attributes in `criteria`.
        ///
        /// - Parameters:
        ///   - criteria: Criteria that identify the item and configure its operations.
        ///   - attributes: Attributes applied when the item is written but not used to
        ///     find it, such as ``KeychainCriterion/accessible(_:)`` or
        ///     ``KeychainCriterion/accessControl(_:)``.
        public init(criteria: [KeychainCriterion], attributes: [KeychainCriterion] = []) {
            self.criteria = criteria
            self.attributes = attributes
        }

        /// Deletes the keychain item matching ``criteria``.
        ///
        /// Removing an item that doesn't exist succeeds, matching ``getData()``, which
        /// returns `nil` in that case.
        ///
        /// - Throws: ``KeychainError`` when the Security framework cannot delete the
        ///   matching item.
        public func remove() throws(KeychainError) {
            do throws(KeychainError) {
                try criteria.delete()
            } catch .itemNotFound {
                return
            }
        }

        func retrieve() throws(KeychainError) -> KeychainRecord? {
            try criteria.retrieve()
        }

        /// The criteria used to create a new item.
        var createCriteria: [KeychainCriterion] {
            criteria + attributes
        }

        /// The attributes written when an existing item is updated.
        ///
        /// Access control can't be changed after creation, so it's excluded.
        func updateAttributes(data: Data) -> [KeychainCriterion] {
            [.data(data)] + attributes.filter {
                if case .accessControl = $0 {
                    return false
                }
                return true
            }
        }

        /// Builds the write-only attributes shared by the password factories.
        static func writeAttributes(
            accessibility: KeychainCriterion.Accessibility?,
            accessControl: SecAccessControl?,
            label: String?,
            comment: String?,
            description: String?
        ) -> [KeychainCriterion] {
            var attributes: [KeychainCriterion] = []
            if let accessibility {
                attributes.append(.accessible(accessibility))
            }
            if let accessControl {
                attributes.append(.accessControl(accessControl))
            }
            if let label {
                attributes.append(.label(label))
            }
            if let comment {
                attributes.append(.comment(comment))
            }
            if let description {
                attributes.append(.description(description))
            }
            return attributes
        }

        /// Builds the operation criteria shared by the password factories.
        static func options(useDataProtectionKeychain: Bool, contextProvider: KeychainCriterion?) -> [KeychainCriterion] {
            var options: [KeychainCriterion] = []
            if useDataProtectionKeychain {
                options.append(.useDataProtectionKeychain)
            }
            if let contextProvider {
                options.append(contextProvider)
            }
            return options
        }

        /// Creates the item, or updates it when an equivalent item already exists.
        func write(data: Data) throws(KeychainError) {
            try [KeychainCriterion].upsert(
                create: { () throws(KeychainError) in try createCriteria.create(data: data) },
                update: { () throws(KeychainError) in try criteria.update(attributes: updateAttributes(data: data)) }
            )
        }
    }

#endif
