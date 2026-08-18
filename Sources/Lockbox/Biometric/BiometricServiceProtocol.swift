#if canImport(Security)
#if !os(watchOS) && !os(tvOS) && !os(visionOS)
import Combine
import Foundation
import LocalAuthentication

/// An interface for storing and retrieving credentials protected by biometric authentication.
@MainActor public protocol BiometricServiceProtocol {

    /// The biometric authentication technology supported by the device.
    var supportedType: LABiometryType { get }

    /// A Boolean value that indicates whether biometric authentication is configured
    /// and can be evaluated.
    var isProperlyConfigured: Bool { get }

    /// A Boolean value that indicates whether the device supports biometric authentication.
    var supportedByDevice: Bool { get }

    /// A Boolean value that indicates whether protected credentials are present.
    var hasCredentials: Bool { get }

    /// Authenticates the user and stores credentials protected by biometrics.
    ///
    /// - Parameters:
    ///   - email: The username or email address to store.
    ///   - password: The password to store.
    /// - Throws: An error if biometric authentication or keychain storage fails.
    func save(email: String, password: String) async throws

    /// Authenticates the user and retrieves the protected credentials.
    ///
    /// - Returns: The stored username and password.
    /// - Throws: An error if biometric authentication or keychain access fails.
    func retrieve() async throws -> BiometricServiceResult

    /// Removes the protected credentials.
    func forget()
}
#endif

#endif
