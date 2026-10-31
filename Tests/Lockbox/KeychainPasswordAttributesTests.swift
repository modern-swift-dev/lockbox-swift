#if canImport(Security)
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
                protection: .accessControl(try makeAccessControl())
            )

            let query = try #require(password.criteria.query as? [String: AnyObject])
            #expect(query[kSecAttrAccessControl as String] == nil)
            #expect(query[kSecAttrService as String] as? String == "com.example.attributes")
        }

        @Test func accessControlIsAppliedOnCreateWithoutAccessibility() throws {
            let password = KeychainPassword.generic(
                service: "com.example.attributes",
                account: "user",
                protection: .accessControl(try makeAccessControl())
            )

            let query = try #require(password.createCriteria.query as? [String: AnyObject])
            #expect(query[kSecAttrAccessControl as String] != nil)
            #expect(query[kSecAttrAccessible as String] == nil)
            #expect(query[kSecAttrAccount as String] as? String == "user")
        }

        @Test func accessControlIsIncludedInUpdateAttributes() throws {
            let accessControl = try makeAccessControl()
            let password = KeychainPassword.generic(
                service: "com.example.attributes",
                account: "user",
                protection: .accessControl(accessControl)
            )
            let data = Data("secret".utf8)

            let attributes = try #require(password.updateAttributes(data: data).query as? [String: AnyObject])
            #expect(attributes[kSecAttrAccessControl as String] === accessControl)
            #expect(attributes[kSecAttrAccessible as String] == nil)
            #expect(attributes[kSecValueData as String] as? Data == data)
        }

        @Test func accessibilityIsAppliedOnCreateAndUpdateWithoutAccessControl() throws {
            let password = KeychainPassword.generic(
                service: "com.example.attributes",
                account: "user",
                protection: .accessibility(.afterFirstUnlockThisDeviceOnly)
            )
            let queries = [
                try #require(password.createCriteria.query as? [String: AnyObject]),
                try #require(password.updateAttributes(data: Data()).query as? [String: AnyObject])
            ]

            for query in queries {
                #expect(
                    query[kSecAttrAccessible as String] as? String
                        == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
                )
                #expect(query[kSecAttrAccessControl as String] == nil)
            }
        }

        @Test func writeAttributesAreExcludedFromMatchingQuery() throws {
            let password = KeychainPassword.generic(
                service: "com.example.attributes",
                account: "user",
                protection: .accessibility(.afterFirstUnlock),
                label: "Label",
                comment: "Comment",
                description: "Description"
            )

            let query = try #require(password.criteria.query as? [String: AnyObject])
            #expect(query[kSecAttrAccessible as String] == nil)
            #expect(query[kSecAttrLabel as String] == nil)
            #expect(query[kSecAttrComment as String] == nil)
            #expect(query[kSecAttrDescription as String] == nil)
        }

        @Test func writeAttributesAreAppliedOnCreateAndUpdate() throws {
            let url = try #require(URL(string: "https://example.com/login"))
            let password = KeychainPassword.internet(
                url: url,
                account: "user",
                protection: .accessibility(.afterFirstUnlock),
                label: "Label",
                comment: "Comment",
                description: "Description"
            )
            let queries = [
                try #require(password.createCriteria.query as? [String: AnyObject]),
                try #require(password.updateAttributes(data: Data()).query as? [String: AnyObject])
            ]

            for query in queries {
                #expect(query[kSecAttrAccessible as String] as? String == kSecAttrAccessibleAfterFirstUnlock as String)
                #expect(query[kSecAttrLabel as String] as? String == "Label")
                #expect(query[kSecAttrComment as String] as? String == "Comment")
                #expect(query[kSecAttrDescription as String] as? String == "Description")
            }
        }

        @Test func internetAccessControlIsAppliedOnCreateAndUpdate() throws {
            let url = try #require(URL(string: "https://example.com/login"))
            let accessControl = try makeAccessControl()
            let password = KeychainPassword.internet(
                url: url,
                account: "user",
                protection: .accessControl(accessControl)
            )
            let queries = [
                try #require(password.createCriteria.query as? [String: AnyObject]),
                try #require(password.updateAttributes(data: Data()).query as? [String: AnyObject])
            ]

            for query in queries {
                #expect(query[kSecAttrAccessControl as String] === accessControl)
                #expect(query[kSecAttrAccessible as String] == nil)
            }
        }

        @Test func publicInitializerKeepsCriteriaAndAttributes() throws {
            let password = KeychainPassword(
                criteria: [.securityClass(.genericPassword), .service("com.example.init"), .account("user")],
                attributes: [.accessible(.afterFirstUnlock)]
            )

            let query = try #require(password.criteria.query as? [String: AnyObject])
            #expect(query[kSecAttrService as String] as? String == "com.example.init")
            #expect(query[kSecAttrAccessible as String] == nil)
            let createQuery = try #require(password.createCriteria.query as? [String: AnyObject])
            #expect(createQuery[kSecAttrAccessible as String] as? String == kSecAttrAccessibleAfterFirstUnlock as String)
        }

        @Test func internetPasswordHasNoServiceAttribute() throws {
            let url = try #require(URL(string: "https://example.com"))
            let withDomain = KeychainPassword.internet(url: url, securityDomain: "realm", account: "user")
            let withoutDomain = KeychainPassword.internet(url: url, account: "user")

            let query = try #require(withDomain.criteria.query as? [String: AnyObject])
            #expect(query[kSecAttrService as String] == nil)
            #expect(query[kSecAttrSecurityDomain as String] as? String == "realm")
            let plainQuery = try #require(withoutDomain.criteria.query as? [String: AnyObject])
            #expect(plainQuery[kSecAttrService as String] == nil)
            #expect(plainQuery[kSecAttrSecurityDomain as String] == nil)
        }

        @Test func dataProtectionKeychainIsOptIn() throws {
            let url = try #require(URL(string: "https://example.com"))
            let defaults = [
                KeychainPassword.generic(service: "com.example.dp", account: "user"),
                KeychainPassword.internet(url: url, account: "user")
            ]
            let optedIn = [
                KeychainPassword.generic(service: "com.example.dp", account: "user", useDataProtectionKeychain: true),
                KeychainPassword.internet(url: url, account: "user", useDataProtectionKeychain: true)
            ]

            for password in defaults {
                let query = try #require(password.criteria.query as? [String: AnyObject])
                #expect(query[kSecUseDataProtectionKeychain as String] == nil)
            }
            for password in optedIn {
                let query = try #require(password.criteria.query as? [String: AnyObject])
                #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
            }
        }

        @Test func handleWithoutAttributesCreatesWithCriteriaOnly() {
            let password = KeychainPassword.generic(service: "com.example.attributes", account: "user")

            #expect(password.attributes.isEmpty)
            #expect(password.createCriteria.count == password.criteria.count)
        }
    }
#endif
