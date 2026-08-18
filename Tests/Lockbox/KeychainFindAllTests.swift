#if os(macOS)
import Foundation
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

@Suite(.serialized) struct KeychainFindAllTests {

    private let testService = "com.slkeychain.findall.\(UUID().uuidString)"

    private func cleanup(service: String, account: String) {
        let password = KeychainPassword.generic(service: service, account: account)
        try? password.remove()
    }

    private func skipIfNoKeychainAccess() throws {
        try #require(isKeychainAccessible(), "Keychain access not available (missing entitlements)")
    }

    @Test func findAllReturnsEmptyArrayWhenNoItems() throws {
        try skipIfNoKeychainAccess()
        let service = "empty_service_\(UUID().uuidString)"
        let records = try KeychainCriterion.findAll(service: service, accessGroup: nil)
        #expect(records.isEmpty)
    }

    @Test func findAllReturnsSingleItem() throws {
        try skipIfNoKeychainAccess()
        let account = "findone_\(UUID().uuidString)"
        let password = KeychainPassword.generic(service: testService, account: account)

        defer { cleanup(service: testService, account: account) }

        try password.set(string: "password")

        let records = try KeychainCriterion.findAll(service: testService, accessGroup: nil)
        #expect(records.count >= 1)

        let found = records.first { $0.account == account }
        #expect(found != nil)
        #expect(found?.service == testService)
    }

    @Test func findAllReturnsMultipleItems() throws {
        try skipIfNoKeychainAccess()
        let account1 = "find1_\(UUID().uuidString)"
        let account2 = "find2_\(UUID().uuidString)"
        let password1 = KeychainPassword.generic(service: testService, account: account1)
        let password2 = KeychainPassword.generic(service: testService, account: account2)

        defer {
            cleanup(service: testService, account: account1)
            cleanup(service: testService, account: account2)
        }

        try password1.set(string: "password1")
        try password2.set(string: "password2")

        let records = try KeychainCriterion.findAll(service: testService, accessGroup: nil)

        let found1 = records.first { $0.account == account1 }
        let found2 = records.first { $0.account == account2 }

        #expect(found1 != nil)
        #expect(found2 != nil)
    }

    @Test func allGenericPasswordReturnsKeychainPasswords() throws {
        try skipIfNoKeychainAccess()
        let account1 = "allgen1_\(UUID().uuidString)"
        let account2 = "allgen2_\(UUID().uuidString)"
        let password1 = KeychainPassword.generic(service: testService, account: account1)
        let password2 = KeychainPassword.generic(service: testService, account: account2)

        defer {
            cleanup(service: testService, account: account1)
            cleanup(service: testService, account: account2)
        }

        try password1.set(string: "pw1")
        try password2.set(string: "pw2")

        let passwords = try KeychainPassword.allGenericPassword(service: testService)

        #expect(passwords.count >= 2)
    }
}
#endif
