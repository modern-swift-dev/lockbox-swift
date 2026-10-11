#if canImport(Security)
    #if os(macOS) || os(iOS)
        import Foundation
        import LocalAuthentication
        @testable import Lockbox
        import Testing

        @Suite(.serialized) struct LAContextPolicyEvaluationResultTests {

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
                let error = NSError(domain: "TestDomain", code: 456)
                let result = LAContext.PolicyEvaluationResult.from(result: false, error: error)
                if case let .underlying(wrapped) = result {
                    #expect((wrapped as NSError).code == 456)
                } else {
                    Issue.record("Expected .underlying when error is provided")
                }
            }

            @Test func fromWithSuccessReturnsSuccess() {
                let result = LAContext.PolicyEvaluationResult.from(result: true, error: nil)

                #expect(({
                    if case .success = result {
                        return true
                    }; return false })())
            }

            @Test func fromWithFailureReturnsFailed() {
                let result = LAContext.PolicyEvaluationResult.from(result: false, error: nil)

                #expect(({
                    if case .failed = result {
                        return true
                    }; return false })())
            }
        }
    #endif

#endif
