#if canImport(Security)
#if !os(watchOS) && !os(tvOS) && !os(visionOS)
import Foundation
import LocalAuthentication

/// An interface for evaluating Local Authentication policies and keychain access controls.
public protocol LocalAuthenticationServiceProtocol: Sendable {

    /// The context whose authentication state is shared with keychain operations.
    var context: LAContext { get }

    /// The biometric authentication technology supported by the device.
    var supportedType: LABiometryType { get }

    /// Determines whether the context can evaluate an authentication policy.
    ///
    /// - Parameter policy: The policy whose availability should be checked.
    /// - Returns: `true` when the policy can be evaluated; otherwise, `false`.
    func isProperlyConfigured(for policy: LAPolicy) -> Bool

    /// Evaluates the access control protecting a keychain item.
    ///
    /// - Parameters:
    ///   - access: The access-control object protecting the keychain item.
    ///   - operation: The keychain operation to authorize.
    ///   - reason: The localized explanation shown to the user, or `nil` to use
    ///     the service's default reason.
    /// - Returns: The outcome of the authentication evaluation.
    func evaluate(
        access: SecAccessControl,
        operation: LAAccessControlOperation,
        reason: String?
    ) async -> LAContext.PolicyEvaluationResult

    /// Evaluates a Local Authentication policy independently of keychain access control.
    ///
    /// - Parameters:
    ///   - policy: The authentication policy to evaluate.
    ///   - operation: The keychain operation associated with the evaluation.
    ///   - reason: The localized explanation shown to the user, or `nil` to use
    ///     the service's default reason.
    /// - Returns: The outcome of the authentication evaluation.
    func evaluate(
        policy: LAPolicy,
        operation: LAAccessControlOperation,
        reason: String?
    ) async -> LAContext.PolicyEvaluationResult

    /// Invalidates the context and clears its cached authentication state.
    func invalidate()
}

#endif

#endif
