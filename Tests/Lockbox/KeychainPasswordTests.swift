#if canImport(Security)
    import Foundation
    #if canImport(LocalAuthentication)
        import LocalAuthentication
    #endif
    @testable import Lockbox
    import Testing

    @Suite(.serialized) struct KeychainPasswordGenericTests {

        private let testService = "com.slkeychain.test.\(UUID().uuidString)"

        private func cleanup(service: String, account: String) {
            let password = KeychainPassword.generic(service: service, account: account)
            try? password.remove()
        }

        @Test func genericPasswordCreation() throws {
            let account = "test_\(UUID().uuidString)"
            let password = KeychainPassword.generic(service: testService, account: account)

            #expect(!password.criteria.isEmpty)

            let query = try #require(password.criteria.query as? [String: AnyObject])
            #expect(query[kSecClass as String] as? String == kSecClassGenericPassword as String)
            #expect(query[kSecAttrService as String] as? String == testService)
            #expect(query[kSecAttrAccount as String] as? String == account)
        }

        @Test func genericPasswordWithAccessGroup() throws {
            let account = "test_\(UUID().uuidString)"
            let password = KeychainPassword.generic(
                service: testService,
                account: account,
                accessGroup: "group.com.test"
            )

            let query = try #require(password.criteria.query as? [String: AnyObject])
            #expect(query[kSecAttrAccessGroup as String] as? String == "group.com.test")
        }

        @Test func genericPasswordWithSynchronizable() throws {
            let account = "test_\(UUID().uuidString)"
            let password = KeychainPassword.generic(
                service: testService,
                account: account,
                synchronizable: true
            )

            let query = try #require(password.criteria.query as? [String: AnyObject])
            let syncValue = try #require(query[kSecAttrSynchronizable as String] as? Bool)
            #expect(syncValue)
        }

        @Test(.requiresKeychain) func setAndGetString() throws {
            let account = "test_string_\(UUID().uuidString)"
            let password = KeychainPassword.generic(service: testService, account: account)

            defer { cleanup(service: testService, account: account) }

            try password.set(string: "mySecretPassword")
            let retrieved = try password.getString()

            #expect(retrieved == "mySecretPassword")
        }

        @Test(.requiresKeychain) func setAndGetData() throws {
            let account = "test_data_\(UUID().uuidString)"
            let password = KeychainPassword.generic(service: testService, account: account)

            defer { cleanup(service: testService, account: account) }

            let testData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
            try password.set(data: testData)
            let retrieved = try password.getData()

            #expect(retrieved == testData)
        }

        @Test(.requiresKeychain) func updateExistingString() throws {
            let account = "test_update_\(UUID().uuidString)"
            let password = KeychainPassword.generic(service: testService, account: account)

            defer { cleanup(service: testService, account: account) }

            try password.set(string: "initialPassword")
            try password.set(string: "updatedPassword")
            let retrieved = try password.getString()

            #expect(retrieved == "updatedPassword")
        }

        @Test(.requiresKeychain) func removePassword() throws {
            let account = "test_remove_\(UUID().uuidString)"
            let password = KeychainPassword.generic(service: testService, account: account)

            try password.set(string: "toBeRemoved")
            try password.remove()

            let retrieved = try password.getString()
            #expect(retrieved == nil)
        }

        @Test(.requiresKeychain) func writeAttributesAreStoredAndReplacedOnUpdate() throws {
            let account = "test_attributes_\(UUID().uuidString)"
            defer { cleanup(service: testService, account: account) }

            let first = KeychainPassword.generic(
                service: testService,
                account: account,
                protection: .accessibility(.whenUnlocked),
                label: "First label",
                comment: "First comment",
                description: "First description"
            )
            try first.set(string: "first")

            let second = KeychainPassword.generic(
                service: testService,
                account: account,
                protection: .accessibility(.afterFirstUnlock),
                label: "Second label",
                comment: "Second comment",
                description: "Second description"
            )
            try second.set(string: "second")

            let record = try #require(try second.retrieve())
            #expect(record.label == "Second label")
            #expect(record.comment == "Second comment")
            #expect(record.itemDescription == "Second description")
            #expect(try first.getString() == "second")
        }

        @Test(.requiresKeychain) func removeMissingItemSucceeds() throws {
            let account = "missing_\(UUID().uuidString)"
            let password = KeychainPassword.generic(service: testService, account: account)

            try password.remove()
            try password.set(string: "value")
            try password.remove()
            try password.remove()

            #expect(try password.getString() == nil)
        }

        @Test(.requiresKeychain) func criteriaDeleteOfMissingItemStillThrowsItemNotFound() throws {
            let password = KeychainPassword.generic(service: testService, account: "missing_\(UUID().uuidString)")

            #expect(throws: KeychainError.itemNotFound) {
                try password.criteria.delete()
            }
        }

        @Test(.requiresKeychain, arguments: ["", "héllo wörld 🔐", "line\nbreak\u{0}nul"])
        func stringRoundTripsAsUTF8(value: String) throws {
            let account = "utf8_\(UUID().uuidString)"
            let password = KeychainPassword.generic(service: testService, account: account)
            defer { cleanup(service: testService, account: account) }

            try password.set(string: value)

            #expect(try password.getString() == value)
            #expect(try password.getData() == Data(value.utf8))
        }

        @Test(.requiresKeychain) func getStringThrowsInvalidUTF8WhenDataIsNotUTF8() throws {
            let account = "invalid_utf8_\(UUID().uuidString)"
            let password = KeychainPassword.generic(service: testService, account: account)
            defer { cleanup(service: testService, account: account) }

            try password.set(data: Data([0xFF, 0xFE]))

            do {
                _ = try password.getString()
                Issue.record("Expected invalid UTF-8")
            } catch {
                guard case .invalidUTF8 = error else {
                    Issue.record("Unexpected error: \(error)")
                    return
                }
            }
            #expect(try password.getData() == Data([0xFF, 0xFE]))
        }

        @Test(.requiresKeychain) func getStringReturnsNilWhenNotExists() throws {
            let account = "nonexistent_\(UUID().uuidString)"
            let password = KeychainPassword.generic(service: testService, account: account)

            let retrieved = try password.getString()
            #expect(retrieved == nil)
        }
    }

#endif
