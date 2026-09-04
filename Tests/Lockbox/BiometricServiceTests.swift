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

    @Test func missingCredentialsThrowsUnconfiguredAfterAuthenticationEvaluation() async {
        let authentication = MockLocalAuthenticationService(result: .success)
        let keychain = MockBiometricCredentialStore(authentication: authentication)
        let service = BiometricService(
            service: "BiometricServiceTests.missing.\(UUID().uuidString)",
            localAuthenticationService: authentication,
            keychainOverride: keychain
        )

        do {
            _ = try await service.retrieve()
            Issue.record("Expected missing credentials")
        } catch BiometricServiceError.unconfigured {
            #expect(authentication.evaluationCount == 1)
            #expect(keychain.operations == [.read(afterEvaluations: 1)])
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test func existenceQueryCannotRequestSecretsOrPresentAuthentication() throws {
        let name = "BiometricServiceTests.exists.\(UUID().uuidString)"
        let authentication = MockLocalAuthenticationService(result: .success)
        let service = BiometricService(service: name, localAuthenticationService: authentication)
        #expect(authentication.evaluationCount == 0)
        let query = service.credentialExistenceQuery
        #expect(query[kSecReturnData as String] == nil)
        #expect(query[kSecReturnAttributes as String] as? Bool == true)
        let context = try #require(query[kSecUseAuthenticationContext as String] as? LAContext)
        #expect(context.interactionNotAllowed)
        #expect(context !== authentication.context)
    }

    @Test func cancellationIsPreservedEvenWithoutCredentials() async {
        let authentication = MockLocalAuthenticationService(result: .underlying(LAError(.userCancel)))
        let keychain = MockBiometricCredentialStore(authentication: authentication)
        let service = BiometricService(
            service: "BiometricServiceTests.cancel.\(UUID().uuidString)",
            localAuthenticationService: authentication,
            keychainOverride: keychain
        )
        do {
            _ = try await service.retrieve()
            Issue.record("Expected cancellation")
        } catch BiometricServiceError.cancelled {
            #expect(authentication.evaluationCount == 1)
            #expect(keychain.operations.isEmpty)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

}

private final class MockBiometricCredentialStore: BiometricCredentialStore, @unchecked Sendable {
    enum Operation: Equatable {
        case read(afterEvaluations: Int)
        case write(afterEvaluations: Int)
        case remove
    }

    enum StorageError: Error {
        case writeFailed
    }

    private let authentication: MockLocalAuthenticationService
    private let failsWrites: Bool
    private let lock = NSLock()
    private var data: Data?
    private var recordedOperations: [Operation] = []

    var operations: [Operation] {
        lock.withLock { recordedOperations }
    }

    init(authentication: MockLocalAuthenticationService, failsWrites: Bool = false) {
        self.authentication = authentication
        self.failsWrites = failsWrites
    }

    func getData() throws -> Data? {
        lock.withLock {
            recordedOperations.append(.read(afterEvaluations: authentication.evaluationCount))
            return data
        }
    }

    func set(data: Data) throws {
        try lock.withLock {
            recordedOperations.append(.write(afterEvaluations: authentication.evaluationCount))
            if failsWrites {
                throw StorageError.writeFailed
            }
            self.data = data
        }
    }

    func remove() throws {
        lock.withLock {
            recordedOperations.append(.remove)
            data = nil
        }
    }
}

private final class MockLocalAuthenticationService: LocalAuthenticationServiceProtocol, @unchecked Sendable {
    let context = LAContext()
    let supportedType: LABiometryType
    let isConfigured: Bool
    let result: LAContext.PolicyEvaluationResult
    private let lock = NSLock()
    private var evaluations = 0
    private var records = 0

    var evaluationCount: Int {
        lock.withLock { evaluations }
    }

    var recordCount: Int {
        lock.withLock { records }
    }

    init(
        supportedType: LABiometryType = .faceID,
        isConfigured: Bool = true,
        result: LAContext.PolicyEvaluationResult = .failed
    ) {
        self.supportedType = supportedType
        self.isConfigured = isConfigured
        self.result = result
    }

    func isProperlyConfigured(for _: LAPolicy) -> Bool {
        isConfigured
    }

    func evaluate(
        access _: SecAccessControl,
        operation _: LAAccessControlOperation,
        reason _: String?
    ) async -> LAContext.PolicyEvaluationResult {
        lock.withLock { evaluations += 1 }
        return result
    }

    func evaluate(
        policy _: LAPolicy,
        operation _: LAAccessControlOperation,
        reason _: String?
    ) async -> LAContext.PolicyEvaluationResult {
        .failed
    }

    func recordBiometricState() throws {
        lock.withLock { records += 1 }
    }

    func invalidate() {
        context.invalidate()
    }
}
#endif

#endif
