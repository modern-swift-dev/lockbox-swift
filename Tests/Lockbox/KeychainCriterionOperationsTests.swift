#if canImport(Security)
    import Foundation
    #if canImport(LocalAuthentication)
        import LocalAuthentication
    #endif
    @testable import Lockbox
    import Testing

    @Suite(.serialized) struct KeychainCriterionOperationsTests {

        private let testService = "com.slkeychain.criteriontest.\(UUID().uuidString)"

        private func cleanup(criteria: [KeychainCriterion]) {
            try? criteria.delete()
        }

        @Test(.requiresKeychain) func createAndRetrieve() throws {
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

        @Test(.requiresKeychain) func existsReturnsTrueWhenItemExists() throws {
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

        @Test(.requiresKeychain) func existsReturnsFalseWhenItemNotExists() throws {
            let account = "notexists_\(UUID().uuidString)"
            let criteria: [KeychainCriterion] = [
                .securityClass(.genericPassword),
                .service(testService),
                .account(account)
            ]

            let exists = try criteria.exists()
            #expect(exists == false)
        }

        @Test(.requiresKeychain) func updateExistingItem() throws {
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

        @Test(.requiresKeychain) func deleteItem() throws {
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

        @Test(.requiresKeychain) func createOrUpdateCreatesNewItem() throws {
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

        @Test(.requiresKeychain) func createOrUpdateUpdatesExistingItem() throws {
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

        @Test(.requiresKeychain) func createDuplicateThrowsError() throws {
            let account = "duplicate_\(UUID().uuidString)"
            let criteria: [KeychainCriterion] = [
                .securityClass(.genericPassword),
                .service(testService),
                .account(account)
            ]

            defer { cleanup(criteria: criteria) }

            let testData = try #require("original".data(using: .utf8))
            try criteria.create(data: testData)

            #expect(throws: KeychainError.duplicateItem) {
                try criteria.create(data: testData)
            }
        }
    }

#endif
