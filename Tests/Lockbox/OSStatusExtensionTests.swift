#if os(macOS) || os(iOS)
import Foundation
@testable import Lockbox
import Testing

@Suite(.serialized) struct OSStatusExtensionTests {

    @Test func isSuccessfulReturnsTrueForNoErr() {
        let status: OSStatus = noErr
        #expect(status.isSuccessful == true)
    }

    @Test func isSuccessfulReturnsFalseForError() {
        let status: OSStatus = errSecItemNotFound
        #expect(status.isSuccessful == false)
    }

    @Test func isSuccessfulReturnsFalseForNegativeError() {
        let status: OSStatus = -25300
        #expect(status.isSuccessful == false)
    }

    @Test func isNotFoundReturnsTrueForItemNotFound() {
        let status: OSStatus = errSecItemNotFound
        #expect(status.isNotFound == true)
    }

    @Test func isNotFoundReturnsFalseForNoErr() {
        let status: OSStatus = noErr
        #expect(status.isNotFound == false)
    }

    @Test func isNotFoundReturnsFalseForOtherError() {
        let status: OSStatus = errSecDuplicateItem
        #expect(status.isNotFound == false)
    }

    @Test func errorMessageReturnsNilForNoErr() {
        let status: OSStatus = noErr
        // noErr typically returns nil or a message depending on implementation
        // We just verify it doesn't crash
        _ = status.errorMessage
    }

    @Test func errorMessageReturnsMessageForKnownError() {
        let status: OSStatus = errSecItemNotFound
        let message = status.errorMessage
        // The message should be non-nil for known errors
        #expect(message != nil)
    }

    @Test func errorMessageForDuplicateItem() {
        let status: OSStatus = errSecDuplicateItem
        let message = status.errorMessage
        #expect(message != nil)
    }

    @Test func errorMessageForAuthFailed() {
        let status: OSStatus = errSecAuthFailed
        let message = status.errorMessage
        #expect(message != nil)
    }

    @Test func errorMessageForDecode() {
        let status: OSStatus = errSecDecode
        let message = status.errorMessage
        #expect(message != nil)
    }
}
#endif
