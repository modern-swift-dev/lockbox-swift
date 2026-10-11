#if canImport(Security)
    import Foundation
    @testable import Lockbox
    import Testing

    struct KeychainFindAllCriteriaTests {

        @Test func synchronizableAnyQueryValue() throws {
            let query = try #require([KeychainCriterion.synchronizableAny].query as? [String: AnyObject])
            #expect(query[kSecAttrSynchronizable as String] as? String == kSecAttrSynchronizableAny as String)
        }

        @Test func findAllMatchesSynchronizableAndDeviceOnlyItems() throws {
            let criteria = KeychainCriterion.findAllCriteria(
                type: .genericPassword,
                service: "com.example.findall",
                accessGroup: "group.example",
                accessibility: .afterFirstUnlock
            )
            let query = try #require(criteria.query as? [String: AnyObject])

            #expect(query[kSecAttrSynchronizable as String] as? String == kSecAttrSynchronizableAny as String)
            #expect(query[kSecAttrService as String] as? String == "com.example.findall")
            #expect(query[kSecAttrAccessGroup as String] as? String == "group.example")
            #expect(query[kSecAttrAccessible as String] as? String == kSecAttrAccessibleAfterFirstUnlock as String)
            #expect(query[kSecMatchLimit as String] as? String == kSecMatchLimitAll as String)
            #expect(query[kSecReturnData as String] as? Bool == false)
        }

        @Test func findAllWithoutServiceOmitsServiceAttribute() throws {
            let criteria = KeychainCriterion.findAllCriteria(
                type: .internetPassword,
                service: nil,
                accessGroup: nil,
                accessibility: nil
            )
            let query = try #require(criteria.query as? [String: AnyObject])

            #expect(query[kSecAttrService as String] == nil)
            #expect(query[kSecClass as String] as? String == kSecClassInternetPassword as String)
        }

        @Test func internetPasswordSearchFiltersByServerAndSecurityDomain() throws {
            let criteria = KeychainPassword.internetPasswordSearchCriteria(
                server: "example.com",
                securityDomain: "realm",
                accessGroup: nil,
                useDataProtectionKeychain: true
            )
            let query = try #require(criteria.query as? [String: AnyObject])

            #expect(query[kSecClass as String] as? String == kSecClassInternetPassword as String)
            #expect(query[kSecAttrService as String] == nil)
            #expect(query[kSecAttrServer as String] as? String == "example.com")
            #expect(query[kSecAttrSecurityDomain as String] as? String == "realm")
            #expect(query[kSecAttrSynchronizable as String] as? String == kSecAttrSynchronizableAny as String)
            #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        }

        @Test func genericPasswordHandlesKeepRecordSynchronizability() throws {
            let records = [
                KeychainRecord([
                    kSecAttrAccount as String: "synced" as AnyObject,
                    kSecAttrSynchronizable as String: kCFBooleanTrue
                ]),
                KeychainRecord([
                    kSecAttrAccount as String: "local" as AnyObject,
                    kSecAttrSynchronizable as String: kCFBooleanFalse
                ])
            ]

            let handles = KeychainPassword.genericPasswords(
                from: records,
                service: "com.example.findall",
                accessGroup: nil,
                useDataProtectionKeychain: false
            )
            let queries = try handles.map { try #require($0.criteria.query as? [String: AnyObject]) }

            #expect(queries.count == 2)
            #expect(queries[0][kSecAttrAccount as String] as? String == "synced")
            #expect(queries[0][kSecAttrSynchronizable as String] as? Bool == true)
            #expect(queries[1][kSecAttrAccount as String] as? String == "local")
            #expect(queries[1][kSecAttrSynchronizable as String] as? Bool == false)
        }

        @Test func foundHandlesKeepDataProtectionKeychainChoice() throws {
            let records = [KeychainRecord([kSecAttrAccount as String: "user" as AnyObject])]
            let handles = KeychainPassword.genericPasswords(
                from: records,
                service: "com.example.findall",
                accessGroup: nil,
                useDataProtectionKeychain: true
            ) + KeychainPassword.internetPasswords(from: records, useDataProtectionKeychain: true)

            for handle in handles {
                let query = try #require(handle.criteria.query as? [String: AnyObject])
                #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
            }
        }
    }
#endif
