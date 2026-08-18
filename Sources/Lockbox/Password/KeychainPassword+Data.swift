#if canImport(Security)
import Foundation

public extension KeychainPassword {
    /// Retrieves the raw data stored by this keychain item.
    ///
    /// - Returns: The stored data, or `nil` when no item matches ``criteria``.
    /// - Throws: ``KeychainError`` when the Security framework cannot retrieve the
    ///   item, for example because authentication or keychain access fails.
    func getData() throws -> Data? {
        try retrieve()?.data
    }

    /// Creates or updates this keychain item with raw data.
    ///
    /// If an item matching ``criteria`` already exists, its data is replaced;
    /// otherwise a new item is created. Use this method for arbitrary binary data.
    ///
    /// - Parameter data: The data to store securely in the keychain.
    /// - Throws: ``KeychainError`` when the Security framework cannot determine
    ///   whether the item exists, create it, or update it.
    func set(data: Data) throws {
        try criteria.createOrUpdate(data: data)
    }
}

#endif
