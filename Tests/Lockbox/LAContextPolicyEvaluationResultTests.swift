#if canImport(Security)
#if os(macOS) || os(iOS)
import Foundation
import LocalAuthentication
@testable import Lockbox
import Testing

@Suite(.serialized) struct LAContextPolicyEvaluationResultTests {

    @Test func biometricChangedCaseTrue() {
        let result = LAContext.PolicyEvaluationResult.biometricChanged(true)
        if case let .biometricChanged(value) = result {
            #expect(value == true)
        } else {
            Issue.record("Expected .biometricChanged")
        }
    }

    @Test func biometricChangedCaseFalse() {
        let result = LAContext.PolicyEvaluationResult.biometricChanged(false)
        if case let .biometricChanged(value) = result {
            #expect(value == false)
        } else {
            Issue.record("Expected .biometricChanged")
        }
    }

    @Test func underlyingCase() {
        let error = NSError(domain: "TestDomain", code: 123)
        let result = LAContext.PolicyEvaluationResult.underlying(error)
        if case let .underlying(wrapped) = result {
            #expect((wrapped as NSError).code == 123)
        } else {
            Issue.record("Expected .underlying")
        }
    }

    @Test func fromWithErrorReturnsUnderlying() {
        let context = LAContext()
        let error = NSError(domain: "TestDomain", code: 456)
        let result = LAContext.PolicyEvaluationResult.from(
            context: context,
            operation: .useItem,
            result: false,
            error: error
        )
        if case let .underlying(wrapped) = result {
            #expect((wrapped as NSError).code == 456)
        } else {
            Issue.record("Expected .underlying when error is provided")
        }
    }

    @Test func fromWithSuccessReturnsSuccess() {
        let context = LAContext()
        let result = LAContext.PolicyEvaluationResult.from(
            context: context,
            operation: .useItem,
            result: true,
            error: nil
        )
        // Without biometric data changed, true result should return success
        #expect(({ if case .success = result { return true }; if case .biometricChanged = result { return true }; return false })())
    }

    @Test func fromWithFailureReturnsFailed() {
        let context = LAContext()
        let result = LAContext.PolicyEvaluationResult.from(
            context: context,
            operation: .useItem,
            result: false,
            error: nil
        )
        // Without biometric data changed and false result should return failed
        #expect(({ if case .failed = result { return true }; if case .biometricChanged = result { return true }; return false })())
    }

    @Test func fromWithCreateItemOperation() {
        let context = LAContext()
        let result = LAContext.PolicyEvaluationResult.from(
            context: context,
            operation: .createItem,
            result: true,
            error: nil
        )
        // Should handle createItem operation
        #expect(({ if case .success = result { return true }; if case .biometricChanged = result { return true }; return false })())
    }
}
#endif

#endif
