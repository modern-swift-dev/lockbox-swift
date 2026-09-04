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

        service.invalidate()
        #expect(!service.context.canEvaluatePolicy(policy, error: nil))
        #expect(!service.isProperlyConfigured(for: policy))
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
