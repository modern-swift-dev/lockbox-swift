#if canImport(Security)
    #if os(iOS)
        import Foundation
        import LocalAuthentication

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
        /// try await service.save(email: "user@example.com", password: "secret")
        /// let result = try await service.retrieve()
        /// ```
        public final class BiometricService: BiometricServiceProtocol, Sendable {

            /// The encoded representation of credentials stored in the keychain.
            public struct Credentials: Codable {
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

            /// Access Control
            private let accessControl: SecAccessControl

            /// The Keychain Item that wraps the credentials
            private let keychain: any BiometricCredentialStore

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
            /// This property does not authenticate or decode the stored credentials. Keychain
            /// access errors are treated as an absence of credentials.
            public var hasCredentials: Bool {
                SecItemCopyMatching(credentialExistenceQuery as CFDictionary, nil) == errSecSuccess
            }

            /// Attribute-only queries use a separate context so cached prompt settings cannot enable UI.
            var credentialExistenceQuery: [String: Any] {
                let context = LAContext()
                context.interactionNotAllowed = true
                var query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: account,
                    kSecAttrSynchronizable as String: synchronizable,
                    kSecReturnAttributes as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne,
                    kSecUseAuthenticationContext as String: context
                ]
                if let accessGroup {
                    query[kSecAttrAccessGroup as String] = accessGroup
                }
                return query
            }

            /// Creates a biometric credential service for a generic-password keychain item.
            ///
            /// - Parameters:
            ///   - service: The keychain service name. By default, the main bundle identifier.
            ///   - account: The account name used to identify the keychain item.
            ///   - accessGroup: The keychain access group, or `nil` to use the app's default access.
            ///   - synchronizable: Must be `false`. Device-only biometric credentials cannot sync;
            ///     `save` rejects `true` before authentication.
            ///   - localAuthenticationService: The local-authentication service used for prompts
            ///     and as the keychain authentication context.
            public convenience init(
                // swiftlint:disable:next force_unwrapping
                service: String = Bundle.main.bundleIdentifier!,
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
                keychainOverride: (any BiometricCredentialStore)?
            ) {
                self.service = service
                self.account = account
                self.accessGroup = accessGroup
                self.synchronizable = synchronizable
                self.localAuthenticationService = localAuthenticationService

                accessControl = SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault,
                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                    .biometryCurrentSet,
                    nil
                    // swiftlint:disable:next force_unwrapping
                )!
                keychain = keychainOverride ?? KeychainPassword.generic(
                    service: service,
                    account: account,
                    accessGroup: accessGroup,
                    synchronizable: synchronizable,
                    accessControl: accessControl,
                    contextProvider: { localAuthenticationService.context }
                )
            }

            /// Saves credentials after successfully evaluating biometric access control.
            ///
            /// Existing data for the configured service and account is replaced.
            ///
            /// - Parameters:
            ///   - email: The username or email address to store.
            ///   - password: The password to store.
            /// - Throws: ``BiometricServiceError`` when biometrics are unsupported, not
            ///   configured, rejected, or unavailable, or synchronization is requested.
            ///   Encoding, keychain, and biometric-baseline storage errors are wrapped in ``BiometricServiceError/underlying(_:)``.
            public func save(email: String, password: String) async throws {
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
                    access: accessControl,
                    operation: .createItem,
                    reason: nil
                )
                do {
                    switch result {
                        case .success,
                             .biometricChanged(true):
                            let credentials = Credentials(username: email, password: password)
                            let data = try JSONEncoder().encode(credentials)
                            try keychain.set(data: data)
                            try localAuthenticationService.recordBiometricState()

                        case .failed,
                             .biometricChanged(false):
                            throw BiometricServiceError.failed

                        case let .underlying(error):
                            let biometricError = BiometricServiceError.from(error: error)
                            if biometricError.isLockedOut {
                                forget()
                            }
                            throw biometricError
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
            ///   configured, credentials are absent, authentication fails, or stored data
            ///   cannot be read or decoded.
            public func retrieve() async throws -> BiometricServiceResult {
                guard supportedByDevice else {
                    throw BiometricServiceError.unsupported
                }
                guard isProperlyConfigured else {
                    throw BiometricServiceError.unconfigured
                }
                let result = await localAuthenticationService.evaluate(
                    access: accessControl,
                    operation: .useItem,
                    reason: nil
                )
                do {
                    switch result {
                        case .success,
                             .biometricChanged(true):
                            guard let data = try keychain.getData() else {
                                throw BiometricServiceError.unconfigured
                            }

                            let credentials: Credentials = try JSONDecoder().decode(Credentials.self, from: data)
                            if case .biometricChanged(true) = result {
                                return .biometricChanged(username: credentials.username, password: credentials.password)
                            }
                            return .success(username: credentials.username, password: credentials.password)
                        case .failed,
                             .biometricChanged(false):
                            throw BiometricServiceError.failed
                        case let .underlying(error):
                            let biometricError = BiometricServiceError.from(error: error)
                            if biometricError.isLockedOut {
                                forget()
                            }
                            throw biometricError
                    }
                } catch {
                    if error is BiometricServiceError {
                        throw error
                    }
                    throw BiometricServiceError.underlying(error)
                }
            }

            /// Removes the stored credentials from the keychain.
            ///
            /// Removal errors are ignored. Call ``hasCredentials`` to inspect whether data
            /// remains accessible afterward.
            public func forget() {
                try? keychain.remove()
            }
        }

    #endif

#endif
