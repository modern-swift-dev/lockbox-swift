#if canImport(Security)
    import Foundation
    @testable import Lockbox
    import Testing

    struct KeychainErrorTests {

        @Test func descriptionSurvivesErrorErasureAndNSErrorBridging() {
            let error: any Error = KeychainError.underlyingError(status: -25300, message: "Item not found")
            #expect(error.localizedDescription == "-25300 - Item not found")
            #expect((error as NSError).localizedDescription == "-25300 - Item not found")
        }

        @Test func underlyingErrorWithMessageLocalizedDescription() {
            let error = KeychainError.underlyingError(status: -25300, message: "Item not found")
            #expect(error.localizedDescription == "-25300 - Item not found")
        }

        @Test func underlyingErrorWithoutMessageLocalizedDescription() {
            let error = KeychainError.underlyingError(status: -25300, message: nil)
            #expect(error.localizedDescription == "-25300 - unknown error")
        }

        @Test func underlyingErrorWithEmptyMessage() {
            let error = KeychainError.underlyingError(status: -12345, message: "")
            #expect(error.localizedDescription == "-12345 - ")
        }

        @Test(arguments: [
            (errSecItemNotFound, KeychainError.itemNotFound),
            (errSecDuplicateItem, .duplicateItem),
            (errSecInteractionNotAllowed, .interactionNotAllowed),
            (errSecMissingEntitlement, .missingEntitlement),
            (errSecAuthFailed, .authenticationFailed),
            (errSecUserCanceled, .userCanceled)
        ])
        func knownStatusesMapToTypedCases(status: OSStatus, expected: KeychainError) {
            let error = KeychainError(status: status)
            #expect(error == expected)
            #expect(error.status == status)
        }

        @Test func unknownStatusKeepsStatusAndSystemMessage() {
            let error = KeychainError(status: errSecDecode)
            #expect(error == .underlyingError(status: errSecDecode, message: errSecDecode.errorMessage))
            #expect(error.status == errSecDecode)
        }

        @Test func equalityIgnoresTheMessage() {
            #expect(KeychainError.underlyingError(status: errSecDecode, message: nil) == KeychainError(status: errSecDecode))
            #expect(KeychainError.underlyingError(status: -1, message: "a") == .underlyingError(status: -1, message: "b"))
        }

        @Test func equalityComparesTheStatus() {
            #expect(KeychainError.underlyingError(status: -1, message: "a") != .underlyingError(status: -2, message: "a"))
            #expect(KeychainError.itemNotFound != .duplicateItem)
            #expect(KeychainError.underlyingError(status: errSecItemNotFound, message: nil) == .itemNotFound)
        }

        @Test func decodeStatusIsNotReportedAsInvalidUTF8() {
            guard case .underlyingError(errSecDecode, _) = KeychainError(status: errSecDecode) else {
                Issue.record("errSecDecode from Keychain Services isn't a UTF-8 failure")
                return
            }
        }

        @Test func invalidUTF8ReportsDecodeStatusAndItsOwnMessage() {
            let error: any Error = KeychainError.invalidUTF8
            #expect(KeychainError.invalidUTF8.status == errSecDecode)
            #expect(error.localizedDescription == "\(errSecDecode) - The stored data isn't valid UTF-8.")
        }

        @Test(arguments: [
            KeychainError.itemNotFound,
            .duplicateItem,
            .interactionNotAllowed,
            .missingEntitlement,
            .authenticationFailed,
            .userCanceled,
            .invalidUTF8,
            .underlyingError(status: errSecParam, message: nil)
        ])
        func statusRoundTripsThroughInitializer(error: KeychainError) {
            #expect(KeychainError(status: error.status) == error)
        }

        @Test func typedCaseDescriptionIncludesStatusAndSystemMessage() throws {
            let message = try #require(errSecDuplicateItem.errorMessage)
            #expect(KeychainError.duplicateItem.localizedDescription == "\(errSecDuplicateItem) - \(message)")
        }
    }
#endif
