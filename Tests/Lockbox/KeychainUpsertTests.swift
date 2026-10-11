#if canImport(Security)
    import Foundation
    @testable import Lockbox
    import Security
    import Testing

    struct KeychainUpsertTests {
        @Test func successfulCreationDoesNotUpdate() throws {
            var creates = 0
            var updates = 0
            try [KeychainCriterion].upsert(create: { creates += 1 }, update: { updates += 1 })
            #expect(creates == 1)
            #expect(updates == 0)
        }

        @Test func concurrentInsertionRecoversByUpdating() throws {
            var updates = 0
            try [KeychainCriterion].upsert(
                create: { () throws(KeychainError) in
                    // Another writer has already inserted the same primary key.
                    throw .duplicateItem
                },
                update: { updates += 1 }
            )
            #expect(updates == 1)
        }

        @Test func nonDuplicateCreationErrorDoesNotUpdate() {
            var updates = 0
            do {
                try [KeychainCriterion].upsert(
                    create: { () throws(KeychainError) in throw .authenticationFailed },
                    update: { updates += 1 }
                )
                Issue.record("Expected the creation error")
            } catch {
                // `error` is statically typed as KeychainError.
                #expect(error == .authenticationFailed)
                #expect(updates == 0)
            }
        }

        @Test func updateErrorAfterDuplicateIsPreserved() {
            do {
                try [KeychainCriterion].upsert(
                    create: { () throws(KeychainError) in throw .duplicateItem },
                    update: { () throws(KeychainError) in throw .itemNotFound }
                )
                Issue.record("Expected a concurrent deletion to remain visible")
            } catch {
                // A different process can delete the item between the add and update.
                #expect(error == .itemNotFound)
            }
        }

        @Test func keychainOperationsThrowKeychainErrorStatically() {
            let password = KeychainPassword(criteria: [.securityClass(.genericPassword), .service("typed"), .account("typed")])
            let criteria = password.criteria
            // These assignments compile only when the operations use typed throws.
            let setData: (Data) throws(KeychainError) -> Void = password.set(data:)
            let setString: (String) throws(KeychainError) -> Void = password.set(string:)
            let getData: () throws(KeychainError) -> Data? = password.getData
            let getString: () throws(KeychainError) -> String? = password.getString
            let remove: () throws(KeychainError) -> Void = password.remove
            let exists: () throws(KeychainError) -> Bool = criteria.exists
            let retrieve: () throws(KeychainError) -> KeychainRecord? = criteria.retrieve
            let delete: () throws(KeychainError) -> Void = criteria.delete
            let create: (Data) throws(KeychainError) -> Void = criteria.create(data:)
            let createOrUpdate: (Data) throws(KeychainError) -> Void = criteria.createOrUpdate(data:)
            let findAll: (KeychainCriterion.SecurityClass, String?, String?, KeychainCriterion.Accessibility?, Bool) throws(KeychainError)
                -> [KeychainRecord] = KeychainCriterion.findAll(type:service:accessGroup:accessibility:useDataProtectionKeychain:)
            let allGeneric: (String, String?, Bool) throws(KeychainError) -> [KeychainPassword] = KeychainPassword
                .allGenericPassword(service:accessGroup:useDataProtectionKeychain:)
            let allInternet: (String?, String?, String?, Bool) throws(KeychainError) -> [KeychainPassword] = KeychainPassword
                .allInternetPassword(server:securityDomain:accessGroup:useDataProtectionKeychain:)
            _ = (setData, setString, getData, getString, remove, exists, retrieve, delete, create, createOrUpdate)
            _ = (findAll, allGeneric, allInternet)
        }
    }
#endif
