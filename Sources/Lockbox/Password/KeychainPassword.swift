#if canImport(Security)
import Foundation
import Security

/// A handle for a single generic or internet password item in the keychain.
///
/// Create a handle with ``generic(service:account:accessGroup:synchronizable:accessControl:contextProvider:)``
/// or ``internet(url:authenticationType:service:account:accessGroup:synchronizable:accessControl:contextProvider:)``,
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
    /// such as its service and account. They do not include the item's stored data.
    public let criteria: [KeychainCriterion]

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
}

#endif
