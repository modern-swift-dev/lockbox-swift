#if canImport(Security)
#if os(macOS) || os(iOS)
import Foundation
import LocalAuthentication
@testable import Lockbox
import Testing

@Suite(.serialized) struct BiometricServiceErrorTests {

    @Test func underlyingCase() {
        let underlyingError = NSError(domain: "TestDomain", code: 123)
        let error = BiometricServiceError.underlying(underlyingError)
        if case let .underlying(wrapped) = error {
            #expect((wrapped as NSError).code == 123)
        } else {
            Issue.record("Expected .underlying")
        }
    }

    // MARK: - isLockedOut Property Tests

    @Test func isLockedOutReturnsTrueForLockedOut() {
        let error = BiometricServiceError.lockedOut
        #expect(error.isLockedOut == true)
    }

    @Test func isLockedOutReturnsFalseForUnsupported() {
        let error = BiometricServiceError.unsupported
        #expect(error.isLockedOut == false)
    }

    @Test func isLockedOutReturnsFalseForUnconfigured() {
        let error = BiometricServiceError.unconfigured
        #expect(error.isLockedOut == false)
    }

    @Test func isLockedOutReturnsFalseForFailed() {
        let error = BiometricServiceError.failed
        #expect(error.isLockedOut == false)
    }

    @Test func isLockedOutReturnsFalseForCancelled() {
        let error = BiometricServiceError.cancelled
        #expect(error.isLockedOut == false)
    }

    @Test func isLockedOutReturnsFalseForUnavailable() {
        let error = BiometricServiceError.unavailable
        #expect(error.isLockedOut == false)
    }

    @Test func isLockedOutReturnsFalseForUnknown() {
        let error = BiometricServiceError.unknown
        #expect(error.isLockedOut == false)
    }

    @Test func isLockedOutReturnsFalseForUnderlying() {
        let error = BiometricServiceError.underlying(NSError(domain: "Test", code: 0))
        #expect(error.isLockedOut == false)
    }

    // MARK: - LAError Mapping Tests

    @Test func fromLAErrorBiometryLockout() {
        let laError = LAError(.biometryLockout)
        let error = BiometricServiceError.from(error: laError)
        #expect(error.isLockedOut == true)
    }

    @Test func fromLAErrorBiometryNotAvailable() {
        let laError = LAError(.biometryNotAvailable)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .unsupported = error { return true }; return false })())
    }

    @Test func fromLAErrorBiometryNotEnrolled() {
        let laError = LAError(.biometryNotEnrolled)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .unconfigured = error { return true }; return false })())
    }

    @Test func fromLAErrorPasscodeNotSet() {
        let laError = LAError(.passcodeNotSet)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .unconfigured = error { return true }; return false })())
    }

    @Test func fromLAErrorUserCancel() {
        let laError = LAError(.userCancel)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .cancelled = error { return true }; return false })())
    }

    @Test func fromLAErrorAppCancel() {
        let laError = LAError(.appCancel)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .cancelled = error { return true }; return false })())
    }

    @Test func fromLAErrorSystemCancel() {
        let laError = LAError(.systemCancel)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .cancelled = error { return true }; return false })())
    }

    @Test func fromLAErrorUserFallback() {
        let laError = LAError(.userFallback)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .failed = error { return true }; return false })())
    }

    @Test func fromLAErrorAuthenticationFailed() {
        let laError = LAError(.authenticationFailed)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .failed = error { return true }; return false })())
    }

    @Test func fromLAErrorInvalidContext() {
        let laError = LAError(.invalidContext)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .failed = error { return true }; return false })())
    }

    @Test func fromLAErrorNotInteractive() {
        let laError = LAError(.notInteractive)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .unavailable = error { return true }; return false })())
    }

    #if !os(iOS)
    @Test func fromLAErrorBiometryDisconnected() {
        let laError = LAError(.biometryDisconnected)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .unavailable = error { return true }; return false })())
    }

    @Test func fromLAErrorBiometryNotPaired() {
        let laError = LAError(.biometryNotPaired)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .unconfigured = error { return true }; return false })())
    }

    @Test func fromLAErrorInvalidDimensions() {
        let laError = LAError(.invalidDimensions)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .failed = error { return true }; return false })())
    }

    @Test func fromLAErrorCompanionNotAvailable() {
        let laError = LAError(.companionNotAvailable)
        let error = BiometricServiceError.from(error: laError)
        #expect(({ if case .unavailable = error { return true }; return false })())
    }
    #endif

    // MARK: - Generic Error Mapping Tests

    @Test func fromGenericErrorReturnsUnderlying() {
        let nsError = NSError(domain: "TestDomain", code: 999, userInfo: nil)
        let error = BiometricServiceError.from(error: nsError)
        if case let .underlying(wrapped) = error {
            #expect((wrapped as NSError).code == 999)
        } else {
            Issue.record("Expected .underlying")
        }
    }

    @Test func fromLAErrorWrappedAsGenericError() {
        let laError = LAError(.biometryLockout)
        let error = BiometricServiceError.from(error: laError as Error)
        #expect(error.isLockedOut == true)
    }
}
#endif

#endif
