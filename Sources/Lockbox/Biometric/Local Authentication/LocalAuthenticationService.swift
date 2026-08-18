#if canImport(Security)
#if !os(watchOS) && !os(tvOS) && !os(visionOS)
import Foundation
import LocalAuthentication

/// Evaluates Local Authentication policies and keychain access controls.
///
/// The service owns an `LAContext` configured with localized prompt text. Reuse the
/// instance when keychain operations must share the same authentication context.
///
/// Example:
/// ```swift
/// let service = LocalAuthenticationService(
///     reason: "Unlock app",
///     fallbackTitle: "Use Passcode"
/// )
/// let result = await service.evaluate(
///     policy: .deviceOwnerAuthentication,
///     reason: nil
/// )
/// ```
public final class LocalAuthenticationService: LocalAuthenticationServiceProtocol {

    /// The default localized explanation shown in authentication prompts.
    public let reason: String

    /// The localized title of the fallback button, or `nil` for the system default.
    public let fallbackTitle: String?

    /// The localized title of the cancel button, or `nil` for the system default.
    public let cancelTitle: String?

    /// The strategy used when evaluating keychain access.
    public let mode: LAContext.SecurityMode

    /// The context shared with Local Authentication and keychain operations.
    public let context: LAContext

    /// The biometric authentication technology supported by the device.
    ///
    /// The simulator reports Face ID to support development and testing.
    public var supportedType: LABiometryType {
        #if targetEnvironment(simulator)
        return .faceID
        #else
        return context.biometryType
        #endif
    }

    /// Creates a service with a configured Local Authentication context.
    ///
    /// - Parameters:
    ///   - reason: The default localized explanation shown in authentication prompts.
    ///   - fallbackTitle: The localized fallback-button title, or `nil` for the system default.
    ///   - cancelTitle: The localized cancel-button title, or `nil` for the system default.
    ///   - mode: The strategy used when evaluating keychain access.
    public init(
        reason: String,
        fallbackTitle: String? = nil,
        cancelTitle: String? = nil,
        mode: LAContext.SecurityMode = .adapt(.highest)
    ) {
        self.reason = reason
        self.fallbackTitle = fallbackTitle
        self.cancelTitle = cancelTitle
        self.mode = mode

        let ctx = LAContext()
        ctx.localizedReason = reason
        ctx.localizedFallbackTitle = fallbackTitle
        ctx.localizedCancelTitle = cancelTitle
        context = ctx
    }

    /// Determines whether the context can evaluate an authentication policy.
    ///
    /// - Parameter policy: The policy whose availability should be checked.
    /// - Returns: `true` when the policy can be evaluated; otherwise, `false`.
    public func isProperlyConfigured(for policy: LAPolicy) -> Bool {
        var error: NSError?
        let context: LAContext = context
        context.canEvaluatePolicy(policy, error: &error)
        if let error = error as? LAError {
            switch error.code {
                case .biometryLockout,
                     .biometryNotAvailable,
                     .biometryNotEnrolled,
                     .passcodeNotSet:
                    return false
                default:
                    return false
            }
        }
        return true
    }

    /// Evaluates the access control protecting a keychain item.
    ///
    /// - Parameters:
    ///   - access: The access-control object protecting the item.
    ///   - operation: The keychain operation to authorize.
    ///   - reason: The localized explanation shown to the user, or `nil` to use ``reason``.
    /// - Returns: The outcome of the authentication evaluation.
    public func evaluate(
        access: SecAccessControl,
        operation: LAAccessControlOperation = .useItem,
        reason: String?
    ) async -> LAContext.PolicyEvaluationResult {
        await self.context.evaluate(
            accessControl: access,
            operation: operation,
            securityMode: mode,
            localizedReason: reason ?? self.reason
        )

    }

    /// Evaluates a Local Authentication policy.
    ///
    /// - Parameters:
    ///   - policy: The policy to evaluate.
    ///   - operation: The keychain operation associated with the evaluation.
    ///   - reason: The localized explanation shown to the user, or `nil` to use ``reason``.
    /// - Returns: The outcome of the authentication evaluation.
    public func evaluate(
        policy: LAPolicy = .deviceOwnerAuthentication,
        operation: LAAccessControlOperation = .useItem,
        reason: String?
    ) async -> LAContext.PolicyEvaluationResult {
        await context.evaluate(
            policy: policy,
            operation: operation,
            reason: reason ?? self.reason
        )
    }

    /// Invalidates the context and clears its cached authentication state.
    public func invalidate() {
        context.invalidate()
    }
}
#endif

#endif
