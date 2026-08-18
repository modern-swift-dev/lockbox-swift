#if canImport(Security)
import Foundation

/// Credentials returned by a biometric authentication operation.
public enum BiometricServiceResult {
    /// The operation returned credentials without reporting a biometric-set change.
    ///
    /// - Parameters:
    ///   - username: The stored username.
    ///   - password: The stored password.
    case success(username: String, password: String)

    /// The operation returned credentials after detecting a change to the enrolled biometrics.
    ///
    /// - Parameters:
    ///   - username: The stored username.
    ///   - password: The stored password.
    case biometricChanged(username: String, password: String)
}

#endif
