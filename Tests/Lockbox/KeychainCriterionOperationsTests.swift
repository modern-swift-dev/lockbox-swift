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

@Suite(.serialized) struct KeychainCriterionOperationsTests {

    private let testService = "com.slkeychain.criteriontest.\(UUID().uuidString)"

    private func cleanup(criteria: [KeychainCriterion]) {
        try? criteria.delete()
    }

    private func skipIfNoKeychainAccess() throws {
        try #require(isKeychainAccessible(), "Keychain access not available (missing entitlements)")
    }

    @Test func createAndRetrieve() throws {
        try skipIfNoKeychainAccess()
        let account = "create_\(UUID().uuidString)"
        let criteria: [KeychainCriterion] = [
            .securityClass(.genericPassword),
            .service(testService),
            .account(account)
        ]

        defer { cleanup(criteria: criteria) }

        let testData = try #require("testPassword".data(using: .utf8))
        try criteria.create(data: testData)

        let record = try criteria.retrieve()
        #expect(record != nil)
        #expect(record?.data == testData)
        #expect(record?.service == testService)
        #expect(record?.account == account)
    }

    @Test func existsReturnsTrueWhenItemExists() throws {
        try skipIfNoKeychainAccess()
        let account = "exists_\(UUID().uuidString)"
        let criteria: [KeychainCriterion] = [
            .securityClass(.genericPassword),
            .service(testService),
            .account(account)
        ]

        defer { cleanup(criteria: criteria) }

        let testData = try #require("testPassword".data(using: .utf8))
        try criteria.create(data: testData)

        let exists = try criteria.exists()
        #expect(exists == true)
    }

    @Test func existsReturnsFalseWhenItemNotExists() throws {
        try skipIfNoKeychainAccess()
        let account = "notexists_\(UUID().uuidString)"
        let criteria: [KeychainCriterion] = [
            .securityClass(.genericPassword),
            .service(testService),
            .account(account)
        ]

        let exists = try criteria.exists()
        #expect(exists == false)
    }

    @Test func updateExistingItem() throws {
        try skipIfNoKeychainAccess()
        let account = "update_\(UUID().uuidString)"
        let criteria: [KeychainCriterion] = [
            .securityClass(.genericPassword),
            .service(testService),
            .account(account)
        ]

        defer { cleanup(criteria: criteria) }

        let initialData = try #require("initial".data(using: .utf8))
        try criteria.create(data: initialData)

        let updatedData = try #require("updated".data(using: .utf8))
        try criteria.update(data: updatedData)

        let record = try criteria.retrieve()
        #expect(record?.data == updatedData)
    }

    @Test func deleteItem() throws {
        try skipIfNoKeychainAccess()
        let account = "delete_\(UUID().uuidString)"
        let criteria: [KeychainCriterion] = [
            .securityClass(.genericPassword),
            .service(testService),
            .account(account)
        ]

        let testData = try #require("toDelete".data(using: .utf8))
        try criteria.create(data: testData)
        try criteria.delete()

        let exists = try criteria.exists()
        #expect(exists == false)
    }

    @Test func createOrUpdateCreatesNewItem() throws {
        try skipIfNoKeychainAccess()
        let account = "createOrUpdate_new_\(UUID().uuidString)"
        let criteria: [KeychainCriterion] = [
            .securityClass(.genericPassword),
            .service(testService),
            .account(account)
        ]

        defer { cleanup(criteria: criteria) }

        let testData = try #require("newItem".data(using: .utf8))
        try criteria.createOrUpdate(data: testData)

        let record = try criteria.retrieve()
        #expect(record?.data == testData)
    }

    @Test func createOrUpdateUpdatesExistingItem() throws {
        try skipIfNoKeychainAccess()
        let account = "createOrUpdate_existing_\(UUID().uuidString)"
        let criteria: [KeychainCriterion] = [
            .securityClass(.genericPassword),
            .service(testService),
            .account(account)
        ]

        defer { cleanup(criteria: criteria) }

        let initialData = try #require("initial".data(using: .utf8))
        try criteria.create(data: initialData)

        let updatedData = try #require("updated".data(using: .utf8))
        try criteria.createOrUpdate(data: updatedData)

        let record = try criteria.retrieve()
        #expect(record?.data == updatedData)
    }

    @Test func createDuplicateThrowsError() throws {
        try skipIfNoKeychainAccess()
        let account = "duplicate_\(UUID().uuidString)"
        let criteria: [KeychainCriterion] = [
            .securityClass(.genericPassword),
            .service(testService),
            .account(account)
        ]

        defer { cleanup(criteria: criteria) }

        let testData = try #require("original".data(using: .utf8))
        try criteria.create(data: testData)

        #expect(throws: KeychainError.self) {
            try criteria.create(data: testData)
        }
    }
}
#endif

#endif
