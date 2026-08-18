#if canImport(Security)
#if os(macOS)
import Foundation
import LocalAuthentication
@testable import Lockbox
import Testing

/// Error code for missing entitlements (common in test environments)
private let errSecMissingEntitlement: OSStatus = -34018

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
    } catch let error as KeychainError {
        if case let .underlyingError(status, _) = error, status == errSecMissingEntitlement {
            return false
        }
        return true
    } catch {
        return true
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
