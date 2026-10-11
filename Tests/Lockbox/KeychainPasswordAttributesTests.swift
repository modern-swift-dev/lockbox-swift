#if canImport(Security)
    #if !os(watchOS) && !os(tvOS)
        import Foundation
        @testable import Lockbox
        import Testing

        struct KeychainPasswordAttributesTests {

            private func makeAccessControl() throws -> SecAccessControl {
                try #require(SecAccessControlCreateWithFlags(
                    nil,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    .userPresence,
                    nil
                ))
            }

            @Test func accessControlIsExcludedFromMatchingQuery() throws {
                let password = KeychainPassword.generic(
                    service: "com.example.attributes",
                    account: "user",
                    accessControl: try makeAccessControl()
                )

                let query = try #require(password.criteria.query as? [String: AnyObject])
                #expect(query[kSecAttrAccessControl as String] == nil)
                #expect(query[kSecAttrService as String] as? String == "com.example.attributes")
            }

            @Test func accessControlIsAppliedOnCreate() throws {
                let password = KeychainPassword.generic(
                    service: "com.example.attributes",
                    account: "user",
                    accessControl: try makeAccessControl()
                )

                let query = try #require(password.createCriteria.query as? [String: AnyObject])
                #expect(query[kSecAttrAccessControl as String] != nil)
                #expect(query[kSecAttrAccount as String] as? String == "user")
            }

            @Test func accessControlIsExcludedFromUpdateAttributes() throws {
                let password = KeychainPassword.generic(
                    service: "com.example.attributes",
                    account: "user",
                    accessControl: try makeAccessControl()
                )
                let data = Data("secret".utf8)

                let attributes = try #require(password.updateAttributes(data: data).query as? [String: AnyObject])
                #expect(attributes[kSecAttrAccessControl as String] == nil)
                #expect(attributes[kSecValueData as String] as? Data == data)
            }

            @Test func handleWithoutAttributesCreatesWithCriteriaOnly() {
                let password = KeychainPassword.generic(service: "com.example.attributes", account: "user")

                #expect(password.attributes.isEmpty)
                #expect(password.createCriteria.count == password.criteria.count)
            }
        }
    #endif
#endif
