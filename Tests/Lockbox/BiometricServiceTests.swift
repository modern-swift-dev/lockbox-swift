#if canImport(Security)
    #if os(iOS) || os(macOS)
        import Foundation
        import LocalAuthentication
        @testable import Lockbox
        import Testing

        @Suite(.serialized)
        @MainActor final class BiometricServiceTests {

            /// A temporary Application Support stand-in, so tests never touch real baselines.
            private let baselineDirectory = FileManager.default.temporaryDirectory
                .appendingPathComponent("BiometricServiceTests-\(UUID().uuidString)", isDirectory: true)

            deinit {
                try? FileManager.default.removeItem(at: baselineDirectory)
            }

            private func makeService(
                account: String = "credentials",
                authentication: MockLocalAuthenticationService,
                keychain: MockBiometricCredentialStore? = nil
            ) -> BiometricService {
                BiometricService(
                    service: "BiometricServiceTests",
                    account: account,
                    localAuthenticationService: authentication,
                    keychainOverride: keychain,
                    baselineDirectory: baselineDirectory
                )
            }

            private func baseline(account: String = "credentials") -> BiometricBaseline {
                .forItem(service: "BiometricServiceTests", account: account, accessGroup: nil, in: baselineDirectory)
            }

            private func baselineExists(account: String = "credentials") -> Bool {
                FileManager.default.fileExists(atPath: baseline(account: account).fileURL.path)
            }

            @Test func propertiesReflectLocalAuthenticationService() {
                let localAuthentication = MockLocalAuthenticationService(
                    supportedType: .faceID,
                    isConfigured: true
                )
                let service = makeService(authentication: localAuthentication)

                #expect(service.supportedType == .faceID)
                #expect(service.supportedByDevice)
                #expect(service.isProperlyConfigured)
            }

            @Test func unsupportedDeviceThrowsBeforeEvaluatingAuthentication() async {
                let localAuthentication = MockLocalAuthenticationService(
                    supportedType: .none,
                    isConfigured: true
                )
                let service = makeService(authentication: localAuthentication)

                await #expect(throws: BiometricServiceError.self) {
                    try await service.save(username: "user@example.com", password: "secret")
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
                let service = makeService(authentication: localAuthentication)

                await #expect(throws: BiometricServiceError.self) {
                    try await service.save(username: "user@example.com", password: "secret")
                }
                await #expect(throws: BiometricServiceError.self) {
                    _ = try await service.retrieve()
                }
            }

            @Test func missingCredentialsThrowNoCredentialsBeforeAuthentication() async {
                let authentication = MockLocalAuthenticationService(result: .success)
                let keychain = MockBiometricCredentialStore(authentication: authentication)
                let service = makeService(authentication: authentication, keychain: keychain)

                #expect(await !service.hasCredentials)
                do {
                    _ = try await service.retrieve()
                    Issue.record("Expected missing credentials")
                } catch BiometricServiceError.noCredentials {
                    #expect(authentication.evaluationCount == 0)
                    #expect(keychain.operations.isEmpty)
                } catch {
                    Issue.record("Unexpected error: \(error)")
                }
            }

            @Test func credentialsRemovedDuringAuthenticationThrowNoCredentials() async {
                let authentication = MockLocalAuthenticationService(result: .success)
                let keychain = MockBiometricCredentialStore(authentication: authentication, existsOverride: true)
                let service = makeService(authentication: authentication, keychain: keychain)

                do {
                    _ = try await service.retrieve()
                    Issue.record("Expected missing credentials")
                } catch BiometricServiceError.noCredentials {
                    #expect(authentication.evaluationCount == 1)
                    #expect(keychain.operations == [.read(afterEvaluations: 1)])
                } catch {
                    Issue.record("Unexpected error: \(error)")
                }
            }

            @Test func hasCredentialsReflectsStore() async throws {
                let authentication = MockLocalAuthenticationService(result: .success)
                let keychain = MockBiometricCredentialStore(authentication: authentication)
                let service = makeService(authentication: authentication, keychain: keychain)

                #expect(await !service.hasCredentials)
                try await service.save(username: "user", password: "secret")
                #expect(await service.hasCredentials)
                await service.forget()
                #expect(await !service.hasCredentials)
            }

            @Test func existenceQueryCannotRequestSecretsOrPresentAuthentication() throws {
                let authentication = MockLocalAuthenticationService(result: .success)
                let store = KeychainBiometricCredentialStore(
                    password: .generic(service: "BiometricServiceTests", account: "credentials"),
                    service: "BiometricServiceTests",
                    account: "credentials",
                    accessGroup: "group.example"
                )
                let query = store.existenceQuery
                #expect(query[kSecReturnData as String] == nil)
                #expect(query[kSecReturnAttributes as String] as? Bool == true)
                #expect(query[kSecAttrAccessGroup as String] as? String == "group.example")
                #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
                let context = try #require(query[kSecUseAuthenticationContext as String] as? LAContext)
                #expect(context.interactionNotAllowed)
                #expect(context !== authentication.context)
            }

            @Test func credentialsAreDeviceOnlyInTheirAccessGroup() throws {
                let service = BiometricService(
                    service: "BiometricServiceTests",
                    accessGroup: "group.example",
                    localAuthenticationService: MockLocalAuthenticationService(result: .success)
                )
                let store = try #require(service.keychain as? KeychainBiometricCredentialStore)

                let query = try #require(store.password.criteria.query as? [String: AnyObject])
                #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
                #expect(query[kSecAttrAccessGroup as String] as? String == "group.example")
                #expect(store.existenceQuery[kSecAttrSynchronizable as String] as? Bool == false)
                #expect(store.existenceQuery[kSecAttrAccessGroup as String] as? String == "group.example")
            }

            @Test func credentialsUseTheDataProtectionKeychain() throws {
                let service = makeService(authentication: MockLocalAuthenticationService(result: .success))
                let store = try #require(service.keychain as? KeychainBiometricCredentialStore)

                let query = try #require(store.password.criteria.query as? [String: AnyObject])
                #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
                let createQuery = try #require(store.password.createCriteria.query as? [String: AnyObject])
                #expect(createQuery[kSecAttrAccessControl as String] != nil)
            }

            @Test func itemsThatNeedInteractionStillExist() {
                #expect(KeychainBiometricCredentialStore.indicatesStoredItem(errSecSuccess))
                #expect(KeychainBiometricCredentialStore.indicatesStoredItem(errSecInteractionNotAllowed))
                #expect(!KeychainBiometricCredentialStore.indicatesStoredItem(errSecItemNotFound))
                #expect(!KeychainBiometricCredentialStore.indicatesStoredItem(errSecMissingEntitlement))
            }

            @Test func cancellationIsReportedWithoutReadingCredentials() async {
                let authentication = MockLocalAuthenticationService(result: .underlying(LAError(.userCancel)))
                let keychain = MockBiometricCredentialStore(authentication: authentication, existsOverride: true)
                let service = makeService(authentication: authentication, keychain: keychain)
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

            @Test func lockoutKeepsStoredCredentials() async throws {
                let setup = MockLocalAuthenticationService(result: .success, biometricState: Data([1]))
                let keychain = MockBiometricCredentialStore(authentication: setup)
                try await makeService(authentication: setup, keychain: keychain)
                    .save(username: "user", password: "secret")

                let lockedOut = MockLocalAuthenticationService(result: .underlying(LAError(.biometryLockout)))
                let service = makeService(authentication: lockedOut, keychain: keychain)

                let retrieveError = await #expect(throws: BiometricServiceError.self) {
                    _ = try await service.retrieve()
                }
                let saveError = await #expect(throws: BiometricServiceError.self) {
                    try await service.save(username: "user", password: "new")
                }
                #expect(retrieveError?.isLockedOut == true)
                #expect(saveError?.isLockedOut == true)
                #expect(!keychain.operations.contains(.remove))
                #expect(try keychain.getData() != nil)
                #expect(baselineExists())
            }

            @Test func saveTakesTheUsernameReturnedByRetrieve() async throws {
                let authentication = MockLocalAuthenticationService(result: .success)
                let service: any BiometricServiceProtocol = makeService(
                    authentication: authentication,
                    keychain: MockBiometricCredentialStore(authentication: authentication)
                )

                try await service.save(username: "person@example.com", password: "secret")

                #expect(try await service.retrieve() == .success(username: "person@example.com", password: "secret"))
            }

            @Test func keychainAccessRunsOffTheMainThread() async throws {
                let authentication = MockLocalAuthenticationService(result: .success, biometricState: Data([1]))
                let keychain = MockBiometricCredentialStore(authentication: authentication)
                let service = makeService(authentication: authentication, keychain: keychain)

                _ = await service.hasCredentials
                #expect(keychain.mainThreadAccessCount == 0, "hasCredentials")
                try await service.save(username: "user", password: "secret")
                #expect(keychain.mainThreadAccessCount == 0, "save")
                _ = try await service.retrieve()
                #expect(keychain.mainThreadAccessCount == 0, "retrieve")
                await service.forget()
                #expect(keychain.mainThreadAccessCount == 0, "forget")

                #expect(keychain.operations == [
                    .write(afterEvaluations: 1),
                    .read(afterEvaluations: 2),
                    .remove
                ])
                #expect(keychain.mainThreadAccessCount == 0)
            }

            @Test func saveRecordsBiometricStateForTheItem() async throws {
                let authentication = MockLocalAuthenticationService(result: .success, biometricState: Data([1]))
                let keychain = MockBiometricCredentialStore(authentication: authentication)

                try await makeService(authentication: authentication, keychain: keychain)
                    .save(username: "user", password: "secret")

                #expect(try Data(contentsOf: baseline().fileURL) == Data([1]))
                #expect(keychain.operations == [.write(afterEvaluations: 1)])
            }

            @Test(arguments: [false, true]) func retrieveReportsBiometricChangeSinceSave(changed: Bool) async throws {
                let authentication = MockLocalAuthenticationService(result: .success, biometricState: Data([1]))
                let keychain = MockBiometricCredentialStore(authentication: authentication)
                let service = makeService(authentication: authentication, keychain: keychain)
                try await service.save(username: "user", password: "secret")

                if changed {
                    authentication.biometricState = Data([2])
                }
                let result = try await service.retrieve()

                let expected: BiometricServiceResult = changed
                    ? .biometricChanged(username: "user", password: "secret")
                    : .success(username: "user", password: "secret")
                #expect(result == expected)
                #expect(keychain.operations == [.write(afterEvaluations: 1), .read(afterEvaluations: 2)])
                // Comparing never advances the recorded baseline.
                #expect(try Data(contentsOf: baseline().fileURL) == Data([1]))
            }

            @Test func baselinesAreIndependentPerAccount() async throws {
                let first = MockLocalAuthenticationService(result: .success, biometricState: Data([1]))
                let firstService = makeService(
                    account: "first",
                    authentication: first,
                    keychain: MockBiometricCredentialStore(authentication: first)
                )
                try await firstService.save(username: "first", password: "secret")

                let second = MockLocalAuthenticationService(result: .success, biometricState: Data([2]))
                try await makeService(
                    account: "second",
                    authentication: second,
                    keychain: MockBiometricCredentialStore(authentication: second)
                ).save(username: "second", password: "secret")

                #expect(baseline(account: "first").fileURL != baseline(account: "second").fileURL)
                #expect(try await firstService.retrieve() == .success(username: "first", password: "secret"))
            }

            @Test func baselineIsExcludedFromBackup() async throws {
                let authentication = MockLocalAuthenticationService(result: .success, biometricState: Data([1]))
                try await makeService(
                    authentication: authentication,
                    keychain: MockBiometricCredentialStore(authentication: authentication)
                ).save(username: "user", password: "secret")

                let values = try baseline().fileURL.resourceValues(forKeys: [.isExcludedFromBackupKey])
                #expect(values.isExcludedFromBackup == true)
            }

            @Test func forgetRemovesCredentialsAndBaseline() async throws {
                let authentication = MockLocalAuthenticationService(result: .success, biometricState: Data([1]))
                let keychain = MockBiometricCredentialStore(authentication: authentication)
                let service = makeService(authentication: authentication, keychain: keychain)
                try await service.save(username: "user", password: "secret")
                #expect(baselineExists())

                await service.forget()

                #expect(!baselineExists())
                #expect(keychain.operations.last == .remove)
                #expect(try keychain.getData() == nil)
            }

            @Test func failedKeychainSaveDoesNotRecordBiometricState() async {
                let authentication = MockLocalAuthenticationService(result: .success, biometricState: Data([1]))
                let keychain = MockBiometricCredentialStore(authentication: authentication, failsWrites: true)
                let service = makeService(authentication: authentication, keychain: keychain)
                await #expect(throws: BiometricServiceError.self) {
                    try await service.save(username: "user", password: "secret")
                }
                #expect(authentication.evaluationCount == 1)
                #expect(!baselineExists())
                #expect(keychain.operations == [.write(afterEvaluations: 1)])
            }

            @Test func rejectedAuthenticationDoesNotWriteCredentialsOrBaseline() async throws {
                let authentication = MockLocalAuthenticationService(result: .failed, biometricState: Data([1]))
                let keychain = MockBiometricCredentialStore(authentication: authentication)
                let service = makeService(authentication: authentication, keychain: keychain)
                await #expect(throws: BiometricServiceError.self) {
                    try await service.save(username: "user", password: "secret")
                }
                #expect(!baselineExists())
                #expect(keychain.operations.isEmpty)
            }

        }

        struct BiometricBaselineTests {

            @Test func comparingBiometricStateNeverAdvancesTheBaseline() throws {
                let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
                defer { try? FileManager.default.removeItem(at: directory) }
                let baseline = BiometricBaseline(fileURL: directory.appendingPathComponent("state"))
                let original = Data([1, 2, 3])
                let replacement = Data([4, 5, 6])

                #expect(try !baseline.hasChanged(from: original))
                #expect(!FileManager.default.fileExists(atPath: baseline.fileURL.path))
                try baseline.record(original)
                #expect(try baseline.hasChanged(from: replacement))
                #expect(try baseline.hasChanged(from: replacement))
                #expect(try Data(contentsOf: baseline.fileURL) == original)

                try baseline.record(replacement)
                #expect(try !baseline.hasChanged(from: replacement))
                #expect(try baseline.hasChanged(from: original))

                try baseline.remove()
                try baseline.remove()
                #expect(try !baseline.hasChanged(from: original))
            }

            @Test func itemLocationDependsOnServiceAccountAndAccessGroup() {
                let directory = URL(fileURLWithPath: "/tmp/baselines")
                let base = BiometricBaseline.forItem(service: "service", account: "account", accessGroup: nil, in: directory)

                #expect(base.fileURL.path.hasPrefix("/tmp/baselines/Lockbox/Biometrics/"))
                #expect(base.fileURL == BiometricBaseline.forItem(service: "service", account: "account", accessGroup: nil, in: directory).fileURL)
                #expect(base.fileURL != BiometricBaseline.forItem(service: "other", account: "account", accessGroup: nil, in: directory).fileURL)
                #expect(base.fileURL != BiometricBaseline.forItem(service: "service", account: "other", accessGroup: nil, in: directory).fileURL)
                #expect(base.fileURL != BiometricBaseline.forItem(service: "service", account: "account", accessGroup: "group", in: directory).fileURL)
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
            private let existsOverride: Bool?
            private let lock = NSLock()
            private var data: Data?
            private var recordedOperations: [Operation] = []
            private var mainThreadAccesses = 0

            var operations: [Operation] {
                lock.withLock { recordedOperations }
            }

            /// How many store calls ran on the main thread.
            var mainThreadAccessCount: Int {
                lock.withLock { mainThreadAccesses }
            }

            private func noteThread() {
                if Thread.isMainThread {
                    mainThreadAccesses += 1
                }
            }

            init(authentication: MockLocalAuthenticationService, failsWrites: Bool = false, existsOverride: Bool? = nil) {
                self.authentication = authentication
                self.failsWrites = failsWrites
                self.existsOverride = existsOverride
            }

            func exists() -> Bool {
                lock.withLock {
                    noteThread()
                    return existsOverride ?? (data != nil)
                }
            }

            func getData() throws -> Data? {
                lock.withLock {
                    noteThread()
                    recordedOperations.append(.read(afterEvaluations: authentication.evaluationCount))
                    return data
                }
            }

            func set(data: Data) throws {
                try lock.withLock {
                    noteThread()
                    recordedOperations.append(.write(afterEvaluations: authentication.evaluationCount))
                    if failsWrites {
                        throw StorageError.writeFailed
                    }
                    self.data = data
                }
            }

            func remove() throws {
                lock.withLock {
                    noteThread()
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
            private var state: Data?

            var evaluationCount: Int {
                lock.withLock { evaluations }
            }

            var biometricState: Data? {
                get { lock.withLock { state } }
                set { lock.withLock { state = newValue } }
            }

            init(
                supportedType: LABiometryType = .faceID,
                isConfigured: Bool = true,
                result: LAContext.PolicyEvaluationResult = .failed,
                biometricState: Data? = nil
            ) {
                self.supportedType = supportedType
                self.isConfigured = isConfigured
                self.result = result
                state = biometricState
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
