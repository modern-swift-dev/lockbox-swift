#if os(macOS) || os(iOS)
import Foundation
@testable import Lockbox
import Testing

@Suite(.serialized) struct KeychainErrorTests {

    @Test func encodingFailedLocalizedDescription() {
        let error = KeychainError.encodingFailed
        #expect(error.localizedDescription == "encoding failed")
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
}
#endif
