#if canImport(Security)
    import Foundation

    /// Credentials returned by a biometric authentication operation.
    public enum BiometricServiceResult: Sendable, Equatable {
        /// The operation returned credentials without reporting a biometric-set change.
        ///
        /// - Parameters:
        ///   - username: The stored username.
        ///   - password: The stored password.
        case success(username: String, password: String)

        /// The operation returned credentials, but the enrolled biometrics changed after they were saved.
        ///
        /// - Parameters:
        ///   - username: The stored username.
        ///   - password: The stored password.
        case biometricChanged(username: String, password: String)
    }

#endif
