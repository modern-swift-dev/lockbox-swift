#if canImport(Security)
    #if os(iOS) || os(macOS)
        import Foundation
        import LocalAuthentication

        /// Stores and retrieves credentials in the keychain using biometric access control.
        ///
        /// `BiometricService` protects a generic-password item with the device's current
        /// biometric set. Saving and retrieving credentials prompts for local authentication.
        ///
        /// The item records the biometric state it was saved with. When the enrolled
        /// biometrics change, the keychain makes the item permanently unreadable;
        /// ``retrieve()`` then throws ``BiometricServiceError/biometricChanged`` without
        /// prompting, ``hasCredentials`` is `false`, and ``save(username:password:)``
        /// replaces the item.
        ///
        /// On macOS the item is stored in the data protection keychain, which requires a
        /// signed app with a keychain access group.
        ///
        /// Example:
        /// ```swift
        /// let service = BiometricService(
        ///     service: "com.myapp",
        ///     localAuthenticationService: LocalAuthenticationService(reason: "Unlock credentials")
        /// )
        /// try await service.save(username: "user@example.com", password: "secret")
        /// let credentials = try await service.retrieve()
        /// ```
        public final class BiometricService: BiometricServiceProtocol, Sendable {

            /// The encoded representation of credentials stored in the keychain.
            public struct Credentials: Codable, Sendable, Equatable {
                /// The username associated with the stored credential.
                public let username: String

                /// The password associated with the stored credential.
                public let password: String

                /// Creates credentials, for example in a test double of ``BiometricServiceProtocol``.
                ///
                /// - Parameters:
                ///   - username: The username or email address.
                ///   - password: The password.
                public init(username: String, password: String) {
                    self.username = username
                    self.password = password
                }
            }

            /// The LocalAuthentication service for interacting with biometric hardware
            private let localAuthenticationService: any LocalAuthenticationServiceProtocol

            /// The service name
            private let service: String

            /// The account
            private let account: String

            /// The access group
            private let accessGroup: String?

            /// The Keychain Item that wraps the credentials
            let keychain: any BiometricCredentialStore

            /// The biometric authentication technology supported by the device.
            public var supportedType: LABiometryType {
                localAuthenticationService.supportedType
            }

            /// A Boolean value that indicates whether biometric authentication can be evaluated.
            public var isProperlyConfigured: Bool {
                localAuthenticationService.isProperlyConfigured(for: .deviceOwnerAuthenticationWithBiometrics)
            }

            /// A Boolean value that indicates whether the device reports biometric hardware.
            public var supportedByDevice: Bool {
                supportedType != .none
            }

            /// A Boolean value that indicates whether stored credentials can be retrieved.
            ///
            /// `false` when no credentials are stored, or when ``retrieve()`` would throw
            /// ``BiometricServiceError/biometricChanged`` because the enrolled biometrics
            /// changed since they were saved. It agrees with ``retrieve()``'s checks before
            /// prompting.
            ///
            /// This property does not authenticate or decode the stored credentials; it reads
            /// only the item's attributes. Keychain errors other than a locked device are
            /// treated as an absence of credentials. The keychain query runs off the main actor.
            public var hasCredentials: Bool {
                get async {
                    let (keychain, authentication) = (keychain, localAuthenticationService)
                    return await Self.performOffMainActor {
                        do {
                            try Self.checkStoredItem(keychain.storedItem(), currentState: authentication.biometricState)
                            return true
                        } catch {
                            return false
                        }
                    }
                }
            }

            /// Creates a biometric credential service for a generic-password keychain item.
            ///
            /// - Parameters:
            ///   - service: The keychain service name, such as the app's bundle identifier.
            ///   - account: The account name used to identify the keychain item.
            ///   - accessGroup: The keychain access group, or `nil` to use the app's default access.
            ///   - localAuthenticationService: The local-authentication service used for prompts
            ///     and as the keychain authentication context.
            public convenience init(
                service: String,
                account: String = "credentials",
                accessGroup: String? = nil,
                localAuthenticationService: any LocalAuthenticationServiceProtocol
            ) {
                self.init(
                    service: service,
                    account: account,
                    accessGroup: accessGroup,
                    localAuthenticationService: localAuthenticationService,
                    keychainOverride: nil
                )
            }

            init(
                service: String,
                account: String = "credentials",
                accessGroup: String? = nil,
                localAuthenticationService: any LocalAuthenticationServiceProtocol,
                keychainOverride: (any BiometricCredentialStore)?
            ) {
                self.service = service
                self.account = account
                self.accessGroup = accessGroup
                self.localAuthenticationService = localAuthenticationService

                keychain = keychainOverride ?? KeychainBiometricCredentialStore(
                    password: .generic(
                        service: service,
                        account: account,
                        accessGroup: accessGroup,
                        // Biometric items are device-only, so they never sync through iCloud Keychain.
                        synchronizable: false,
                        // Access-controlled items require the data protection keychain on macOS.
                        useDataProtectionKeychain: true,
                        protection: .accessControl(Self.makeAccessControl()),
                        contextProvider: { localAuthenticationService.context }
                    ),
                    service: service,
                    account: account,
                    accessGroup: accessGroup
                )
            }

            /// Saves credentials after successfully evaluating biometric access control.
            ///
            /// Any credentials already stored for the
            /// configured service and account are deleted, then the new ones are added, so
            /// `save` also replaces credentials that a biometric change made unreadable
            /// (``BiometricServiceError/biometricChanged``) without a call to ``forget()``.
            /// The current biometric state is recorded with the new credentials.
            ///
            /// - Parameters:
            ///   - username: The username or email address to store.
            ///   - password: The password to store.
            /// - Throws: ``BiometricServiceError`` when biometrics are unsupported, not
            ///   configured, rejected, locked out, or unavailable, including when the device
            ///   doesn't report its biometric state. These errors leave stored credentials in
            ///   place; the system clears a lockout after the user enters the device passcode.
            ///   Encoding and keychain errors are wrapped in ``BiometricServiceError/underlying(_:)``.
            ///   If adding the new credentials fails, the old ones have already been deleted.
            public func save(username: String, password: String) async throws {
                guard supportedByDevice else {
                    throw BiometricServiceError.unsupported
                }
                guard isProperlyConfigured else {
                    throw BiometricServiceError.unconfigured
                }

                let authentication = localAuthenticationService
                let result = await authentication.evaluate(
                    access: Self.makeAccessControl(),
                    operation: .createItem,
                    reason: nil
                )
                do {
                    switch result {
                        case .success:
                            guard let state = authentication.biometricState else {
                                throw BiometricServiceError.unavailable
                            }
                            let credentials = Credentials(username: username, password: password)
                            let data = try JSONEncoder().encode(credentials)
                            let keychain = keychain
                            try await Self.performOffMainActor {
                                // Never update a biometric item: an update has to read it, which
                                // needs authentication and fails once a biometric change has
                                // invalidated it. Deleting needs neither.
                                try keychain.remove()
                                try keychain.add(data: data, biometricState: state)
                            }

                        case .failed:
                            throw BiometricServiceError.failed

                        case let .underlying(error):
                            throw BiometricServiceError.from(error: error)
                    }
                } catch {
                    if error is BiometricServiceError {
                        throw error
                    }
                    throw BiometricServiceError.underlying(error)
                }
            }

            /// Authenticates the user and retrieves the stored credentials.
            ///
            /// - Returns: The decoded username and password.
            /// - Throws: ``BiometricServiceError`` when biometrics are unsupported or not
            ///   configured, authentication fails or is locked out, or stored data cannot be
            ///   read or decoded. Two cases are checked before prompting:
            ///   ``BiometricServiceError/noCredentials`` when nothing is stored, and
            ///   ``BiometricServiceError/biometricChanged`` when the enrolled biometrics changed
            ///   since the credentials were saved, so they can never be read; call
            ///   ``save(username:password:)`` to replace them. A lockout leaves stored
            ///   credentials in place; call ``forget()`` if your app should discard them.
            public func retrieve() async throws -> Credentials {
                guard supportedByDevice else {
                    throw BiometricServiceError.unsupported
                }
                guard isProperlyConfigured else {
                    throw BiometricServiceError.unconfigured
                }
                let (keychain, authentication) = (keychain, localAuthenticationService)
                // Don't ask the user to authenticate for credentials they can't read.
                try await Self.performOffMainActor {
                    try Self.checkStoredItem(keychain.storedItem(), currentState: authentication.biometricState)
                }
                let result = await authentication.evaluate(
                    access: Self.makeAccessControl(),
                    operation: .useItem,
                    reason: nil
                )
                do {
                    switch result {
                        case .success:
                            guard let data = try await Self.performOffMainActor({ try keychain.getData() }) else {
                                throw BiometricServiceError.noCredentials
                            }
                            return try JSONDecoder().decode(Credentials.self, from: data)
                        case .failed:
                            throw BiometricServiceError.failed
                        case let .underlying(error):
                            throw BiometricServiceError.from(error: error)
                    }
                } catch {
                    if error is BiometricServiceError {
                        throw error
                    }
                    throw BiometricServiceError.underlying(error)
                }
            }

            /// Removes the stored credentials and their recorded biometric state.
            ///
            /// Removal errors are ignored. Call ``hasCredentials`` to inspect whether data
            /// remains accessible afterward. The keychain work runs off the main actor.
            public func forget() async {
                let keychain = keychain
                await Self.performOffMainActor {
                    try? keychain.remove()
                }
            }

            /// Creates the access control that protects the credentials.
            ///
            /// A new object is created for each use, so none is shared across concurrency domains.
            private nonisolated static func makeAccessControl() -> SecAccessControl {
                SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault,
                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                    .biometryCurrentSet,
                    nil
                    // swiftlint:disable:next force_unwrapping
                )!
            }

            /// Runs blocking keychain and file work away from the main actor.
            ///
            /// Keychain Services blocks the calling thread, which would hang the UI on the
            /// main thread. `@concurrent` always runs the function on the global concurrent
            /// executor. Without it, a nonisolated async function would run on the caller's
            /// actor when the `NonisolatedNonsendingByDefault` upcoming feature is enabled.
            @concurrent
            private static func performOffMainActor<T: Sendable>(
                _ work: @Sendable () throws -> T
            ) async rethrows -> T {
                try work()
            }

            /// Throws the error ``retrieve()`` reports before prompting, if any.
            ///
            /// ``hasCredentials`` uses the same check, so the two always agree.
            ///
            /// A missing recorded or current biometric state counts as a change: without
            /// both, Lockbox can't tell whether the keychain still lets the user read the
            /// item. An item whose attributes can't be read, for example while the device is
            /// locked, passes, and reading it reports the real error.
            private nonisolated static func checkStoredItem(
                _ item: StoredBiometricItem,
                currentState: Data?
            ) throws(BiometricServiceError) {
                switch item {
                    case .missing:
                        throw .noCredentials
                    case let .stored(recordedState):
                        guard let recordedState, recordedState == currentState else {
                            throw .biometricChanged
                        }
                    case .locked:
                        return
                }
            }
        }

    #endif

#endif
