#if canImport(Security)
    import Foundation

    public extension KeychainPassword {

        /// Retrieves this item's data as a UTF-8 string.
        ///
        /// - Returns: The decoded string, or `nil` when no item matches ``criteria``.
        /// - Throws: ``KeychainError/invalidUTF8`` when the item exists but its data isn't
        ///   valid UTF-8; read it with ``getData()`` instead. Otherwise ``KeychainError`` when
        ///   the Security framework cannot retrieve the item.
        func getString() throws(KeychainError) -> String? {
            guard let data = try getData() else {
                return nil
            }
            guard let string = String(data: data, encoding: .utf8) else {
                throw .invalidUTF8
            }
            return string
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
        func set(string: String) throws(KeychainError) {
            try write(data: Data(string.utf8))
        }

    }

#endif
