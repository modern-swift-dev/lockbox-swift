#if canImport(Security)
#if os(iOS)
import Foundation
import LocalAuthentication
@testable import Lockbox
import Testing

@Suite(.serialized)
@MainActor struct BiometricServiceTests {

    @Test func propertiesReflectLocalAuthenticationService() {
        let localAuthentication = MockLocalAuthenticationService(
            supportedType: .faceID,
            isConfigured: true
        )
        let service = BiometricService(
            service: "BiometricServiceTests.properties.\(UUID().uuidString)",
            localAuthenticationService: localAuthentication
        )

        #expect(service.supportedType == .faceID)
        #expect(service.supportedByDevice)
        #expect(service.isProperlyConfigured)
    }

    @Test func unsupportedDeviceThrowsBeforeEvaluatingAuthentication() async {
        let localAuthentication = MockLocalAuthenticationService(
            supportedType: .none,
            isConfigured: true
        )
        let service = BiometricService(
            service: "BiometricServiceTests.unsupported.\(UUID().uuidString)",
            localAuthenticationService: localAuthentication
        )

        await #expect(throws: BiometricServiceError.self) {
            try await service.save(email: "user@example.com", password: "secret")
        }
        await #expect(throws: BiometricServiceError.self) {
            _ = try await service.retrieve()
        }
    }

    @Test func unconfiguredDeviceThrowsBeforeEvaluatingAuthentication() async {
        let localAuthentication = MockLocalAuthenticationService(
            supportedType: .faceID,
            isConfigured: false
        )
        let service = BiometricService(
            service: "BiometricServiceTests.unconfigured.\(UUID().uuidString)",
            localAuthenticationService: localAuthentication
        )

        await #expect(throws: BiometricServiceError.self) {
            try await service.save(email: "user@example.com", password: "secret")
        }
        await #expect(throws: BiometricServiceError.self) {
            _ = try await service.retrieve()
        }
    }

    @Test func missingCredentialsThrowsUnconfiguredBeforeAuthenticationEvaluation() async {
        let localAuthentication = MockLocalAuthenticationService(
            supportedType: .faceID,
            isConfigured: true
        )
        let service = BiometricService(
            service: "BiometricServiceTests.missing.\(UUID().uuidString)",
            localAuthenticationService: localAuthentication
        )
        service.forget()

        await #expect(throws: BiometricServiceError.self) {
            _ = try await service.retrieve()
        }
    }
}

private final class MockLocalAuthenticationService: LocalAuthenticationServiceProtocol, @unchecked Sendable {
    let context = LAContext()
    let supportedType: LABiometryType
    let isConfigured: Bool

    init(supportedType: LABiometryType, isConfigured: Bool) {
        self.supportedType = supportedType
        self.isConfigured = isConfigured
    }

    func isProperlyConfigured(for _: LAPolicy) -> Bool {
        isConfigured
    }

    func evaluate(
        access _: SecAccessControl,
        operation _: LAAccessControlOperation,
        reason _: String?
    ) async -> LAContext.PolicyEvaluationResult {
        .failed
    }

    func evaluate(
        policy _: LAPolicy,
        operation _: LAAccessControlOperation,
        reason _: String?
    ) async -> LAContext.PolicyEvaluationResult {
        .failed
    }

    func invalidate() {
        context.invalidate()
    }
}
#endif

#endif
