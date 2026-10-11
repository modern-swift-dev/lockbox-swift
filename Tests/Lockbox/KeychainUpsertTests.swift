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
                create: {
                    // Another writer has already inserted the same primary key.
                    throw KeychainError.duplicateItem
                },
                update: { updates += 1 }
            )
            #expect(updates == 1)
        }

        @Test func nonDuplicateCreationErrorDoesNotUpdate() {
            var updates = 0
            do {
                try [KeychainCriterion].upsert(
                    create: { throw KeychainError.authenticationFailed },
                    update: { updates += 1 }
                )
                Issue.record("Expected the creation error")
            } catch KeychainError.authenticationFailed {
                #expect(updates == 0)
            } catch {
                Issue.record("Unexpected error: \(error)")
            }
        }

        @Test func updateErrorAfterDuplicateIsPreserved() {
            do {
                try [KeychainCriterion].upsert(
                    create: { throw KeychainError.duplicateItem },
                    update: { throw KeychainError.itemNotFound }
                )
                Issue.record("Expected a concurrent deletion to remain visible")
            } catch KeychainError.itemNotFound {
                // A different process can delete the item between the add and update.
            } catch {
                Issue.record("Unexpected error: \(error)")
            }
        }
    }
#endif
