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
            ///   - reason: The localized explanation shown to the user, or `nil` to use
            ///     the service's default reason.
            /// - Returns: The outcome of the authentication evaluation.
            func evaluate(
                policy: LAPolicy,
                reason: String?
            ) async -> LAContext.PolicyEvaluationResult

            /// An opaque value that changes when the enrolled biometrics change, or `nil`
            /// when it isn't available.
            var biometricState: Data? { get }

            /// Discards the context's cached authentication state.
            ///
            /// After invalidation, ``context`` must return a context that can still evaluate
            /// authentication.
            func invalidate()
        }

        public extension LocalAuthenticationServiceProtocol {
            /// The biometric state hash of the device's enrolled biometrics, or `nil` when
            /// none are enrolled or the state isn't available.
            ///
            /// The value is `domainState.biometry.stateHash`, which changes when the
            /// enrolled biometrics change, the same event that invalidates keychain items
            /// protected with `.biometryCurrentSet`. It ignores paired companion devices, such
            /// as an Apple Watch. A biometric policy is checked first, because a fresh or
            /// invalidated context has no domain state until then.
            var biometricState: Data? {
                let context = context
                _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
                return context.domainState.biometry.stateHash
            }
        }

    #endif

#endif
