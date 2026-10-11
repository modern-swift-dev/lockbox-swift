#if canImport(Security)
    #if os(iOS)
        import Foundation
        import LocalAuthentication
        import os.log

        /// Stores and retrieves credentials in the keychain using biometric access control.
        ///
        /// `BiometricService` protects a generic-password item with the device's current
        /// biometric set. Saving and retrieving credentials prompts for local authentication.
        ///
        /// Example:
        /// ```swift
        /// let service = BiometricService(
        ///     service: "com.myapp",
        ///     localAuthenticationService: LocalAuthenticationService(reason: "Unlock credentials")
        /// )
        /// try await service.save(username: "user@example.com", password: "secret")
        /// let result = try await service.retrieve()
        /// ```
        public final class BiometricService: BiometricServiceProtocol, Sendable {

            /// The encoded representation of credentials stored in the keychain.
            public struct Credentials: Codable, Sendable, Equatable {
                /// The username associated with the stored credential.
                public let username: String

                /// The password associated with the stored credential.
                public let password: String
            }

            /// The LocalAuthentication service for interacting with biometric hardware
            private let localAuthenticationService: any LocalAuthenticationServiceProtocol

            /// The service name
            private let service: String

            /// The account
            private let account: String

            /// The access group
            private let accessGroup: String?

            /// Is it synchronizable through iCloud?
            private let synchronizable: Bool

            /// The Keychain Item that wraps the credentials
            private let keychain: any BiometricCredentialStore

            /// The biometric state recorded when these credentials were saved
            private let baseline: BiometricBaseline

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

            /// A Boolean value that indicates whether the configured keychain item exists.
            ///
            /// This property does not authenticate or decode the stored credentials. Other
            /// keychain errors are treated as an absence of credentials.
            public var hasCredentials: Bool {
                keychain.exists()
            }

            /// Creates a biometric credential service for a generic-password keychain item.
            ///
            /// - Parameters:
            ///   - service: The keychain service name, such as the app's bundle identifier.
            ///   - account: The account name used to identify the keychain item.
            ///   - accessGroup: The keychain access group, or `nil` to use the app's default access.
            ///   - synchronizable: Must be `false`. Device-only biometric credentials cannot sync;
            ///     `save` rejects `true` before authentication.
            ///   - localAuthenticationService: The local-authentication service used for prompts
            ///     and as the keychain authentication context.
            public convenience init(
                service: String,
                account: String = "credentials",
                group accessGroup: String? = nil,
                synchronizable: Bool = false,
                localAuthenticationService: any LocalAuthenticationServiceProtocol
            ) {
                self.init(
                    service: service,
                    account: account,
                    group: accessGroup,
                    synchronizable: synchronizable,
                    localAuthenticationService: localAuthenticationService,
                    keychainOverride: nil
                )
            }

            init(
                service: String,
                account: String = "credentials",
                group accessGroup: String? = nil,
                synchronizable: Bool = false,
                localAuthenticationService: any LocalAuthenticationServiceProtocol,
                keychainOverride: (any BiometricCredentialStore)?,
                baselineDirectory: URL = .applicationSupportDirectory
            ) {
                self.service = service
                self.account = account
                self.accessGroup = accessGroup
                self.synchronizable = synchronizable
                self.localAuthenticationService = localAuthenticationService
                baseline = .forItem(service: service, account: account, accessGroup: accessGroup, in: baselineDirectory)

                keychain = keychainOverride ?? KeychainBiometricCredentialStore(
                    password: .generic(
                        service: service,
                        account: account,
                        accessGroup: accessGroup,
                        synchronizable: synchronizable,
                        accessControl: Self.makeAccessControl(),
                        contextProvider: { localAuthenticationService.context }
                    ),
                    service: service,
                    account: account,
                    accessGroup: accessGroup,
                    synchronizable: synchronizable
                )
            }

            /// Saves credentials after successfully evaluating biometric access control.
            ///
            /// Existing data for the configured service and account is replaced.
            ///
            /// - Parameters:
            ///   - username: The username or email address to store.
            ///   - password: The password to store.
            /// - Throws: ``BiometricServiceError`` when biometrics are unsupported, not
            ///   configured, rejected, locked out, or unavailable, or synchronization is requested.
            ///   A lockout leaves stored credentials in place; the system clears it after the
            ///   user enters the device passcode.
            ///   Encoding, keychain, and biometric-baseline storage errors are wrapped in ``BiometricServiceError/underlying(_:)``.
            public func save(username: String, password: String) async throws {
                guard !synchronizable else {
                    throw BiometricServiceError.synchronizationUnsupported
                }
                guard supportedByDevice else {
                    throw BiometricServiceError.unsupported
                }
                guard isProperlyConfigured else {
                    throw BiometricServiceError.unconfigured
                }

                let result = await localAuthenticationService.evaluate(
                    access: Self.makeAccessControl(),
                    operation: .createItem,
                    reason: nil
                )
                do {
                    switch result {
                        case .success:
                            let credentials = Credentials(username: username, password: password)
                            let data = try JSONEncoder().encode(credentials)
                            let (keychain, baseline, authentication) = (keychain, baseline, localAuthenticationService)
                            try await Self.performOffMainActor {
                                try keychain.set(data: data)
                                if let state = authentication.biometricState {
                                    try baseline.record(state)
                                }
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
            /// - Returns: The decoded username and password in a ``BiometricServiceResult``.
            /// - Throws: ``BiometricServiceError`` when biometrics are unsupported or not
            ///   configured, no credentials are stored (checked before prompting, as
            ///   ``BiometricServiceError/noCredentials``), authentication fails or is locked out,
            ///   or stored data cannot be read or decoded. A lockout leaves stored credentials
            ///   in place; call ``forget()`` if your app should discard them.
            public func retrieve() async throws -> BiometricServiceResult {
                guard supportedByDevice else {
                    throw BiometricServiceError.unsupported
                }
                guard isProperlyConfigured else {
                    throw BiometricServiceError.unconfigured
                }
                let (keychain, baseline, authentication) = (keychain, baseline, localAuthenticationService)
                // Don't ask the user to authenticate for credentials that aren't there.
                guard await Self.performOffMainActor({ keychain.exists() }) else {
                    throw BiometricServiceError.noCredentials
                }
                let result = await localAuthenticationService.evaluate(
                    access: Self.makeAccessControl(),
                    operation: .useItem,
                    reason: nil
                )
                do {
                    switch result {
                        case .success:
                            let (storedData, changed) = try await Self.performOffMainActor {
                                try (keychain.getData(), Self.biometricStateChanged(authentication.biometricState, baseline: baseline))
                            }
                            guard let data = storedData else {
                                throw BiometricServiceError.noCredentials
                            }

                            let credentials: Credentials = try JSONDecoder().decode(Credentials.self, from: data)
                            if changed {
                                return .biometricChanged(username: credentials.username, password: credentials.password)
                            }
                            return .success(username: credentials.username, password: credentials.password)
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
            /// remains accessible afterward.
            public func forget() {
                try? keychain.remove()
                try? baseline.remove()
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
            /// main thread. A nonisolated async function runs on the global concurrent executor.
            private nonisolated static func performOffMainActor<T: Sendable>(
                _ work: @Sendable () throws -> T
            ) async rethrows -> T {
                try work()
            }

            /// Compares the current biometric state with the state recorded at save time.
            ///
            /// An unreadable baseline counts as a change, so callers re-verify the user.
            private nonisolated static func biometricStateChanged(_ state: Data?, baseline: BiometricBaseline) -> Bool {
                guard let state else {
                    return false
                }
                do {
                    return try baseline.hasChanged(from: state)
                } catch {
                    os_log("%{public}@", type: .error, error.localizedDescription)
                    return true
                }
            }
        }

    #endif

#endif
