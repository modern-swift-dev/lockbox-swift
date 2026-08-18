#if os(macOS) || os(iOS)
import Foundation
import Testing

@Suite(.serialized) struct ErrorStatusValueTests {

    @Test func noErrIsZero() {
        #expect(noErr == 0)
    }

    @Test func errSecItemNotFoundValue() {
        #expect(errSecItemNotFound == -25300)
    }

    @Test func errSecDuplicateItemValue() {
        #expect(errSecDuplicateItem == -25299)
    }

    @Test func errSecAuthFailedValue() {
        #expect(errSecAuthFailed == -25293)
    }
}
#endif
