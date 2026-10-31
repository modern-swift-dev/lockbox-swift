#if canImport(Security)
    #if os(iOS) || os(macOS)
        import Foundation
        import LocalAuthentication
        @testable import Lockbox
        import Testing

        @Suite(.serialized)
        @MainActor struct BiometricServiceTests {

            private func makeService(
                authentication: MockLocalAuthenticationService,
                keychain: MockBiometricCredentialStore? = nil
            ) -> BiometricService {
                BiometricService(
                    service: "BiometricServiceTests",
                    localAuthenticationService: authentication,
                    keychainOverride: keychain
                )
            }

            private func encoded(username: String, password: String) throws -> Data {
                try JSONEncoder().encode(BiometricService.Credentials(username: username, password: password))
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
                let keychain = MockBiometricCredentialStore(
                    authentication: authentication,
                    storedItemOverride: .stored(biometricState: Data([1]))
                )
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

            @Test func cancellationIsReportedWithoutReadingCredentials() async throws {
                let authentication = MockLocalAuthenticationService(result: .underlying(LAError(.userCancel)))
                let keychain = try MockBiometricCredentialStore(
                    authentication: authentication,
                    item: .init(data: encoded(username: "user", password: "secret"), biometricState: Data([1]))
                )
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
                let lockedOut = MockLocalAuthenticationService(result: .underlying(LAError(.biometryLockout)))
                let keychain = try MockBiometricCredentialStore(
                    authentication: lockedOut,
                    item: .init(data: encoded(username: "user", password: "secret"), biometricState: Data([1]))
                )
                let service = makeService(authentication: lockedOut, keychain: keychain)

                let retrieveError = await #expect(throws: BiometricServiceError.self) {
                    _ = try await service.retrieve()
                }
                let saveError = await #expect(throws: BiometricServiceError.self) {
                    try await service.save(username: "user", password: "new")
                }
                #expect(retrieveError?.isLockedOut == true)
                #expect(saveError?.isLockedOut == true)
                #expect(keychain.operations.isEmpty)
                #expect(await service.hasCredentials)
            }

            @Test func retrieveReturnsTheSavedCredentials() async throws {
                let authentication = MockLocalAuthenticationService(result: .success)
                let service: any BiometricServiceProtocol = makeService(
                    authentication: authentication,
                    keychain: MockBiometricCredentialStore(authentication: authentication)
                )

                try await service.save(username: "person@example.com", password: "secret")

                #expect(try await service.retrieve() == .init(username: "person@example.com", password: "secret"))
            }

            @Test func keychainAccessRunsOffTheMainThread() async throws {
                let authentication = MockLocalAuthenticationService(result: .success)
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
                    .remove,
                    .add(afterEvaluations: 1),
                    .read(afterEvaluations: 2),
                    .remove
                ])
                #expect(keychain.mainThreadAccessCount == 0)
            }

            @Test func saveRecordsTheBiometricStateWithTheItem() async throws {
                let authentication = MockLocalAuthenticationService(result: .success, biometricState: Data([7]))
                let keychain = MockBiometricCredentialStore(authentication: authentication)

                try await makeService(authentication: authentication, keychain: keychain)
                    .save(username: "user", password: "secret")

                #expect(keychain.recordedBiometricState == Data([7]))
                #expect(keychain.operations == [.remove, .add(afterEvaluations: 1)])
            }

            @Test func saveOverAnExistingItemDeletesThenAdds() async throws {
                let authentication = MockLocalAuthenticationService(result: .success)
                let keychain = MockBiometricCredentialStore(authentication: authentication)
                let service = makeService(authentication: authentication, keychain: keychain)
                try await service.save(username: "user", password: "old")

                try await service.save(username: "user", password: "new")

                #expect(keychain.operations == [
                    .remove, .add(afterEvaluations: 1),
                    .remove, .add(afterEvaluations: 2)
                ])
                #expect(try await service.retrieve() == .init(username: "user", password: "new"))
            }

            @Test func forgetRemovesCredentials() async throws {
                let authentication = MockLocalAuthenticationService(result: .success)
                let keychain = MockBiometricCredentialStore(authentication: authentication)
                let service = makeService(authentication: authentication, keychain: keychain)
                try await service.save(username: "user", password: "secret")

                await service.forget()

                #expect(keychain.operations.last == .remove)
                #expect(keychain.storedItem() == .missing)
            }

            @Test func failedAddIsReported() async {
                let authentication = MockLocalAuthenticationService(result: .success)
                let keychain = MockBiometricCredentialStore(authentication: authentication, failsAdds: true)
                let service = makeService(authentication: authentication, keychain: keychain)
                await #expect(throws: BiometricServiceError.self) {
                    try await service.save(username: "user", password: "secret")
                }
                #expect(authentication.evaluationCount == 1)
                #expect(keychain.operations == [.remove, .add(afterEvaluations: 1)])
                #expect(keychain.storedItem() == .missing)
            }

            @Test func rejectedAuthenticationDoesNotTouchTheKeychain() async throws {
                let authentication = MockLocalAuthenticationService(result: .failed)
                let keychain = try MockBiometricCredentialStore(
                    authentication: authentication,
                    item: .init(data: encoded(username: "user", password: "secret"), biometricState: Data([1]))
                )
                let service = makeService(authentication: authentication, keychain: keychain)
                await #expect(throws: BiometricServiceError.self) {
                    try await service.save(username: "user", password: "new")
                }
                #expect(keychain.operations.isEmpty)
            }

            @Test func storedItemReadsTheRecordedBiometricState() {
                let state = [kSecAttrGeneric as String: Data([1])]
                #expect(KeychainBiometricCredentialStore.storedItem(status: errSecSuccess, attributes: state)
                    == .stored(biometricState: Data([1])))
                #expect(KeychainBiometricCredentialStore.storedItem(status: errSecSuccess, attributes: [:])
                    == .stored(biometricState: nil))
                #expect(KeychainBiometricCredentialStore.storedItem(status: errSecInteractionNotAllowed, attributes: nil)
                    == .locked)
                #expect(KeychainBiometricCredentialStore.storedItem(status: errSecItemNotFound, attributes: nil) == .missing)
                #expect(KeychainBiometricCredentialStore.storedItem(status: errSecMissingEntitlement, attributes: nil)
                    == .missing)
            }

            @Test func addQueryRecordsTheBiometricStateWithTheProtectedData() throws {
                let service = makeService(authentication: MockLocalAuthenticationService(result: .success))
                let store = try #require(service.keychain as? KeychainBiometricCredentialStore)

                let query = store.addQuery(data: Data([9]), biometricState: Data([1]))

                #expect(query[kSecAttrGeneric as String] as? Data == Data([1]))
                #expect(query[kSecValueData as String] as? Data == Data([9]))
                #expect(query[kSecAttrAccessControl as String] != nil)
                #expect(query[kSecAttrService as String] as? String == "BiometricServiceTests")
                #expect(query[kSecAttrAccount as String] as? String == "credentials")
            }

            @Test func changedBiometricsAreReportedBeforePrompting() async throws {
                let authentication = MockLocalAuthenticationService(result: .success, biometricState: Data([2]))
                let keychain = try MockBiometricCredentialStore(
                    authentication: authentication,
                    item: .init(data: encoded(username: "user", password: "secret"), biometricState: Data([1]))
                )
                let service = makeService(authentication: authentication, keychain: keychain)

                #expect(await !service.hasCredentials)
                do {
                    _ = try await service.retrieve()
                    Issue.record("Expected a biometric change")
                } catch BiometricServiceError.biometricChanged {
                    #expect(authentication.evaluationCount == 0)
                    #expect(keychain.operations.isEmpty)
                } catch {
                    Issue.record("Unexpected error: \(error)")
                }
            }

            @Test func saveReplacesCredentialsInvalidatedByABiometricChange() async throws {
                let authentication = MockLocalAuthenticationService(result: .success, biometricState: Data([2]))
                let keychain = try MockBiometricCredentialStore(
                    authentication: authentication,
                    item: .init(data: encoded(username: "user", password: "old"), biometricState: Data([1]))
                )
                let service = makeService(authentication: authentication, keychain: keychain)

                try await service.save(username: "user", password: "new")

                #expect(keychain.operations == [.remove, .add(afterEvaluations: 1)])
                #expect(keychain.recordedBiometricState == Data([2]))
                #expect(await service.hasCredentials)
                #expect(try await service.retrieve() == .init(username: "user", password: "new"))
            }

            @Test func saveWithoutABiometricStateKeepsTheExistingItem() async throws {
                let authentication = MockLocalAuthenticationService(result: .success, biometricState: nil)
                let keychain = try MockBiometricCredentialStore(
                    authentication: authentication,
                    item: .init(data: encoded(username: "user", password: "old"), biometricState: Data([1]))
                )
                let service = makeService(authentication: authentication, keychain: keychain)

                do {
                    try await service.save(username: "user", password: "new")
                    Issue.record("Expected unavailable biometrics")
                } catch BiometricServiceError.unavailable {
                    #expect(keychain.operations.isEmpty)
                } catch {
                    Issue.record("Unexpected error: \(error)")
                }
            }

            /// Whether `hasCredentials` is `true`, and `retrieve()` therefore prompts, for a
            /// stored item and the device's current biometric state.
            @Test(arguments: [
                (StoredBiometricItem.missing, Data([1]), false),
                (.stored(biometricState: Data([1])), Data([1]), true),
                (.stored(biometricState: Data([2])), Data([1]), false),
                // Saved without a recorded state, such as by Lockbox 2.
                (.stored(biometricState: nil), Data([1]), false),
                // The device's current state isn't available.
                (.stored(biometricState: Data([1])), nil, false),
                (.locked, Data([1]), true)
            ] as [(StoredBiometricItem, Data?, Bool)])
            func hasCredentialsAgreesWithRetrieve(item: StoredBiometricItem, currentState: Data?, expected: Bool) async {
                let authentication = MockLocalAuthenticationService(result: .success, biometricState: currentState)
                let keychain = MockBiometricCredentialStore(authentication: authentication, storedItemOverride: item)
                let service = makeService(authentication: authentication, keychain: keychain)

                #expect(await service.hasCredentials == expected)
                _ = try? await service.retrieve()
                #expect((authentication.evaluationCount == 1) == expected)
            }

        }

        private final class MockBiometricCredentialStore: BiometricCredentialStore, @unchecked Sendable {
            enum Operation: Equatable {
                case read(afterEvaluations: Int)
                case add(afterEvaluations: Int)
                case remove
            }

            enum StorageError: Error {
                case addFailed
                case duplicateItem
                case invalidatedByBiometricChange
            }

            /// A stored item and the biometric state recorded with it.
            struct Item {
                let data: Data
                let biometricState: Data?
            }

            private let authentication: MockLocalAuthenticationService
            private let failsAdds: Bool
            private let storedItemOverride: StoredBiometricItem?
            private let lock = NSLock()
            private var item: Item?
            private var recordedOperations: [Operation] = []
            private var contextsUsedForReads: [LAContext] = []
            private var mainThreadAccesses = 0

            var operations: [Operation] {
                lock.withLock { recordedOperations }
            }

            /// The authentication context each read would pass to the keychain.
            var readContexts: [LAContext] {
                lock.withLock { contextsUsedForReads }
            }

            /// The biometric state recorded with the stored item.
            var recordedBiometricState: Data? {
                lock.withLock { item?.biometricState }
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

            init(
                authentication: MockLocalAuthenticationService,
                item: Item? = nil,
                failsAdds: Bool = false,
                storedItemOverride: StoredBiometricItem? = nil
            ) {
                self.authentication = authentication
                self.item = item
                self.failsAdds = failsAdds
                self.storedItemOverride = storedItemOverride
            }

            func storedItem() -> StoredBiometricItem {
                lock.withLock {
                    noteThread()
                    if let storedItemOverride {
                        return storedItemOverride
                    }
                    guard let item else {
                        return .missing
                    }
                    return .stored(biometricState: item.biometricState)
                }
            }

            /// Reads like a `.biometryCurrentSet` item: unreadable once the biometrics change.
            func getData() throws -> Data? {
                let currentState = authentication.biometricState
                let context = authentication.context
                return try lock.withLock {
                    noteThread()
                    recordedOperations.append(.read(afterEvaluations: authentication.evaluationCount))
                    contextsUsedForReads.append(context)
                    guard let item else {
                        return nil
                    }
                    guard item.biometricState == currentState else {
                        throw StorageError.invalidatedByBiometricChange
                    }
                    return item.data
                }
            }

            /// Adds like `SecItemAdd`: fails when an item already exists.
            func add(data: Data, biometricState: Data) throws {
                try lock.withLock {
                    noteThread()
                    recordedOperations.append(.add(afterEvaluations: authentication.evaluationCount))
                    if failsAdds {
                        throw StorageError.addFailed
                    }
                    if item != nil {
                        throw StorageError.duplicateItem
                    }
                    item = Item(data: data, biometricState: biometricState)
                }
            }

            func remove() throws {
                lock.withLock {
                    noteThread()
                    recordedOperations.append(.remove)
                    item = nil
                }
            }
        }

        private final class MockLocalAuthenticationService: LocalAuthenticationServiceProtocol, @unchecked Sendable {
            let supportedType: LABiometryType
            let isConfigured: Bool
            let result: LAContext.PolicyEvaluationResult
            private let lock = NSLock()
            private var currentContext = LAContext()
            private var contextsEvaluated: [LAContext] = []
            private var state: Data?

            /// The context ``invalidate()`` replaced most recently, if any.
            var context: LAContext {
                lock.withLock { currentContext }
            }

            /// The context each evaluation authenticated, in order.
            var evaluatedContexts: [LAContext] {
                lock.withLock { contextsEvaluated }
            }

            var evaluationCount: Int {
                lock.withLock { contextsEvaluated.count }
            }

            var biometricState: Data? {
                get { lock.withLock { state } }
                set { lock.withLock { state = newValue } }
            }

            init(
                supportedType: LABiometryType = .faceID,
                isConfigured: Bool = true,
                result: LAContext.PolicyEvaluationResult = .failed,
                biometricState: Data? = Data([1])
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
                lock.withLock { contextsEvaluated.append(currentContext) }
                return result
            }

            func evaluate(
                policy _: LAPolicy,
                reason _: String?
            ) async -> LAContext.PolicyEvaluationResult {
                .failed
            }

            func invalidate() {
                lock.withLock {
                    currentContext.invalidate()
                    currentContext = LAContext()
                }
            }
        }
    #endif

#endif
