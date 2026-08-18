#if canImport(Security)
import Foundation

public extension KeychainPassword {

    /// Retrieves this item's data as a UTF-8 string.
    ///
    /// - Returns: The decoded string, `nil` when no item matches ``criteria``, or
    ///   `nil` when the stored data is not valid UTF-8.
    /// - Throws: ``KeychainError`` when the Security framework cannot retrieve the item.
    func getString() throws -> String? {
        guard let data = try getData() else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// Creates or updates this keychain item with the UTF-8 representation of a string.
    ///
    /// If an item matching ``criteria`` already exists, its data is replaced;
    /// otherwise a new item is created. Retrieve values written by this method with
    /// ``getString()``.
    ///
    /// - Parameter string: The string to encode as UTF-8 and store in the keychain.
    /// - Throws: ``KeychainError`` when the Security framework cannot determine
    ///   whether the item exists, create it, or update it.
    func set(string: String) throws {
        if let data = string.data(using: .utf8) {
            try criteria.createOrUpdate(data: data)
        }
    }

}

#endif
