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
                    throw KeychainError.underlyingError(status: errSecDuplicateItem, message: nil)
                },
                update: { updates += 1 }
            )
            #expect(updates == 1)
        }

        @Test func nonDuplicateCreationErrorDoesNotUpdate() {
            var updates = 0
            do {
                try [KeychainCriterion].upsert(
                    create: { throw KeychainError.underlyingError(status: errSecAuthFailed, message: nil) },
                    update: { updates += 1 }
                )
                Issue.record("Expected the creation error")
            } catch KeychainError.underlyingError(status: errSecAuthFailed, message: _) {
                #expect(updates == 0)
            } catch {
                Issue.record("Unexpected error: \(error)")
            }
        }

        @Test func updateErrorAfterDuplicateIsPreserved() {
            do {
                try [KeychainCriterion].upsert(
                    create: { throw KeychainError.underlyingError(status: errSecDuplicateItem, message: nil) },
                    update: { throw KeychainError.underlyingError(status: errSecItemNotFound, message: nil) }
                )
                Issue.record("Expected a concurrent deletion to remain visible")
            } catch KeychainError.underlyingError(status: errSecItemNotFound, message: _) {
                // A different process can delete the item between the add and update.
            } catch {
                Issue.record("Unexpected error: \(error)")
            }
        }
    }
#endif
