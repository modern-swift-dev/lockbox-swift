#if canImport(Security)
    #if os(macOS)
        import Foundation
        import LocalAuthentication
        @testable import Lockbox
        import Testing

        /// Checks if the keychain is accessible (has proper entitlements)
        private func isKeychainAccessible() -> Bool {
            let testCriteria: [KeychainCriterion] = [
                .securityClass(.genericPassword),
                .service("com.slkeychain.entitlement.check"),
                .account("test")
            ]
            do {
                _ = try testCriteria.exists()
                return true
            } catch {
                return error != .missingEntitlement
            }
        }

        @Suite(.serialized) struct KeychainPasswordGenericTests {

            private let testService = "com.slkeychain.test.\(UUID().uuidString)"

            private func cleanup(service: String, account: String) {
                let password = KeychainPassword.generic(service: service, account: account)
                try? password.remove()
            }

            private func skipIfNoKeychainAccess() throws {
                try #require(isKeychainAccessible(), "Keychain access not available (missing entitlements)")
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

            @Test func setAndGetString() throws {
                try skipIfNoKeychainAccess()
                let account = "test_string_\(UUID().uuidString)"
                let password = KeychainPassword.generic(service: testService, account: account)

                defer { cleanup(service: testService, account: account) }

                try password.set(string: "mySecretPassword")
                let retrieved = try password.getString()

                #expect(retrieved == "mySecretPassword")
            }

            @Test func setAndGetData() throws {
                try skipIfNoKeychainAccess()
                let account = "test_data_\(UUID().uuidString)"
                let password = KeychainPassword.generic(service: testService, account: account)

                defer { cleanup(service: testService, account: account) }

                let testData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
                try password.set(data: testData)
                let retrieved = try password.getData()

                #expect(retrieved == testData)
            }

            @Test func updateExistingString() throws {
                try skipIfNoKeychainAccess()
                let account = "test_update_\(UUID().uuidString)"
                let password = KeychainPassword.generic(service: testService, account: account)

                defer { cleanup(service: testService, account: account) }

                try password.set(string: "initialPassword")
                try password.set(string: "updatedPassword")
                let retrieved = try password.getString()

                #expect(retrieved == "updatedPassword")
            }

            @Test func removePassword() throws {
                try skipIfNoKeychainAccess()
                let account = "test_remove_\(UUID().uuidString)"
                let password = KeychainPassword.generic(service: testService, account: account)

                try password.set(string: "toBeRemoved")
                try password.remove()

                let retrieved = try password.getString()
                #expect(retrieved == nil)
            }

            @Test func writeAttributesAreStoredAndReplacedOnUpdate() throws {
                try skipIfNoKeychainAccess()
                let account = "test_attributes_\(UUID().uuidString)"
                defer { cleanup(service: testService, account: account) }

                let first = KeychainPassword.generic(
                    service: testService,
                    account: account,
                    accessibility: .whenUnlocked,
                    label: "First label",
                    comment: "First comment",
                    description: "First description"
                )
                try first.set(string: "first")

                let second = KeychainPassword.generic(
                    service: testService,
                    account: account,
                    accessibility: .afterFirstUnlock,
                    label: "Second label",
                    comment: "Second comment",
                    description: "Second description"
                )
                try second.set(string: "second")

                let record = try #require(try second.retrieve())
                #expect(record.label == "Second label")
                #expect(record.comment == "Second comment")
                #expect(record.description == "Second description")
                #expect(try first.getString() == "second")
            }

            @Test func removeMissingItemSucceeds() throws {
                try skipIfNoKeychainAccess()
                let account = "missing_\(UUID().uuidString)"
                let password = KeychainPassword.generic(service: testService, account: account)

                try password.remove()
                try password.set(string: "value")
                try password.remove()
                try password.remove()

                #expect(try password.getString() == nil)
            }

            @Test func criteriaDeleteOfMissingItemStillThrowsItemNotFound() throws {
                try skipIfNoKeychainAccess()
                let password = KeychainPassword.generic(service: testService, account: "missing_\(UUID().uuidString)")

                #expect(throws: KeychainError.itemNotFound) {
                    try password.criteria.delete()
                }
            }

            @Test(arguments: ["", "héllo wörld 🔐", "line\nbreak\u{0}nul"])
            func stringRoundTripsAsUTF8(value: String) throws {
                try skipIfNoKeychainAccess()
                let account = "utf8_\(UUID().uuidString)"
                let password = KeychainPassword.generic(service: testService, account: account)
                defer { cleanup(service: testService, account: account) }

                try password.set(string: value)

                #expect(try password.getString() == value)
                #expect(try password.getData() == Data(value.utf8))
            }

            @Test func getStringReturnsNilWhenNotExists() throws {
                try skipIfNoKeychainAccess()
                let account = "nonexistent_\(UUID().uuidString)"
                let password = KeychainPassword.generic(service: testService, account: account)

                let retrieved = try password.getString()
                #expect(retrieved == nil)
            }
        }
    #endif

#endif
