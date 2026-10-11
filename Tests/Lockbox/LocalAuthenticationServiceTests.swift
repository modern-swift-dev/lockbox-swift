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

        #if !targetEnvironment(simulator)
            @Test func supportedTypeIsInitializedOnFirstAccess() {
                let service = LocalAuthenticationService(reason: "Test biometric availability")
                let initialType = service.supportedType
                _ = service.context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
                #expect(initialType == service.context.biometryType)
            }
        #endif
    }
#endif
