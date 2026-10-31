#if canImport(Security) && (os(macOS) || os(iOS))
    import Foundation
    import LocalAuthentication
    @testable import Lockbox
    import Testing

    @Suite(.serialized) struct LocalAuthenticationServiceTests {

        @Test func configurationMatchesContextBeforeAndAfterInvalidation() {
            let service = LocalAuthenticationService(reason: "Test biometric availability")
            let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
            let available = service.context.canEvaluatePolicy(policy, error: nil)
            #expect(service.isProperlyConfigured(for: policy) == available)

            let previous = service.context
            service.invalidate()
            #expect(!previous.canEvaluatePolicy(policy, error: nil))
            #expect(service.isProperlyConfigured(for: policy) == available)
            #expect(service.context.canEvaluatePolicy(policy, error: nil) == available)
        }

        @Test func invalidateReplacesContextWithSameConfiguration() {
            let service = LocalAuthenticationService(reason: "Unlock", fallbackTitle: "Use Password", cancelTitle: "Not Now")
            let previous = service.context

            service.invalidate()
            let replacement = service.context

            #expect(replacement !== previous)
            #expect(replacement.localizedReason == "Unlock")
            #expect(replacement.localizedFallbackTitle == "Use Password")
            #expect(replacement.localizedCancelTitle == "Not Now")
            #expect(service.context === replacement)
        }

        @Test func invalidatedContextReportsInvalidContext() {
            let service = LocalAuthenticationService(reason: "Unlock")
            let previous = service.context

            service.invalidate()

            var error: NSError?
            _ = previous.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
            #expect(error?.code == LAError.Code.invalidContext.rawValue)
        }

        @Test func biometricStateChecksTheBiometricPolicyFirst() {
            let context = PolicyCheckRecordingContext()
            let service = ContextOnlyAuthenticationService(context: context)

            #expect(service.biometricState == context.domainState.biometry.stateHash)
            #expect(context.checkedPolicies == [.deviceOwnerAuthenticationWithBiometrics])
        }

        #if !targetEnvironment(simulator)
            @Test func supportedTypeIsInitializedOnFirstAccess() {
                let service = LocalAuthenticationService(reason: "Test biometric availability")
                let initialType = service.supportedType
                _ = service.context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
                #expect(initialType == service.context.biometryType)
            }
        #endif
    }

    /// Records which policies were checked, because a fresh context has no domain state
    /// until a biometric policy is checked.
    private final class PolicyCheckRecordingContext: LAContext, @unchecked Sendable {
        private(set) var checkedPolicies: [LAPolicy] = []

        override func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
            checkedPolicies.append(policy)
            return super.canEvaluatePolicy(policy, error: error)
        }
    }

    /// Uses the protocol's default ``LocalAuthenticationServiceProtocol/biometricState``.
    private final class ContextOnlyAuthenticationService: LocalAuthenticationServiceProtocol, @unchecked Sendable {
        let context: LAContext

        init(context: LAContext) {
            self.context = context
        }

        var supportedType: LABiometryType {
            .none
        }

        func isProperlyConfigured(for _: LAPolicy) -> Bool {
            false
        }

        func evaluate(access _: SecAccessControl, operation _: LAAccessControlOperation, reason _: String?) async
            -> LAContext.PolicyEvaluationResult {
            .failed
        }

        func evaluate(policy _: LAPolicy, reason _: String?) async -> LAContext.PolicyEvaluationResult {
            .failed
        }

        func invalidate() {}
    }
#endif
