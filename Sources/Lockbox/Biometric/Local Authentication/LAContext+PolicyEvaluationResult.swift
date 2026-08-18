#if canImport(Security)
#if !os(watchOS) && !os(tvOS) && !os(visionOS)
import Foundation
import LocalAuthentication

public extension LAContext {

    /// The outcome of evaluating a Local Authentication policy or access control.
    enum PolicyEvaluationResult: Sendable {

        /// Evaluation succeeded and the enrolled biometric state is unchanged.
        case success

        /// Evaluation completed without an error but did not authorize the operation.
        case failed

        /// The enrolled biometric state differs from the state recorded during item creation.
        ///
        /// - Parameter result: The authorization result returned by Local Authentication.
        case biometricChanged(Bool)

        /// Local Authentication reported an error.
        ///
        /// - Parameter error: The original evaluation error.
        case underlying(any Error)

        /// Converts a Local Authentication callback into a policy evaluation result.
        ///
        /// - Parameters:
        ///   - context: The context that performed the evaluation.
        ///   - operation: The access-control operation being evaluated.
        ///   - result: The authorization result returned by Local Authentication.
        ///   - error: The evaluation error, if one occurred.
        /// - Returns: A result preserving errors and biometric-state changes before
        ///   mapping the authorization Boolean to ``success`` or ``failed``.
        static func from(context: LAContext, operation: LAAccessControlOperation, result: Bool, error: (any Error)?) -> PolicyEvaluationResult {
            if let error {
                return .underlying(error)
            }

            if context.hasBiometricDataChanged(operation) {
                return .biometricChanged(result)
            }

            if result {
                return .success
            }

            return .failed
        }
    }
}
#endif

#endif
