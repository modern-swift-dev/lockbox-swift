#if canImport(Security)
    import Foundation
    import Security

    /// A handle for a single generic or internet password item in the keychain.
    ///
    /// Create a handle with ``generic(service:account:accessGroup:synchronizable:accessibility:accessControl:label:comment:description:contextProvider:)``
    /// or ``internet(url:authenticationType:service:account:accessGroup:synchronizable:accessibility:accessControl:label:comment:description:contextProvider:)``,
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

        init(criteria: [KeychainCriterion], attributes: [KeychainCriterion] = []) {
            self.criteria = criteria
            self.attributes = attributes
        }

        /// Deletes the keychain item matching ``criteria``.
        ///
        /// - Throws: ``KeychainError`` when the Security framework cannot delete the
        ///   matching item, including when no matching item exists.
        public func remove() throws {
            try criteria.delete()
        }

        func retrieve() throws -> KeychainRecord? {
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

        /// Creates the item, or updates it when an equivalent item already exists.
        func write(data: Data) throws {
            try [KeychainCriterion].upsert(
                create: { try createCriteria.create(data: data) },
                update: { try criteria.update(attributes: updateAttributes(data: data)) }
            )
        }
    }

#endif
