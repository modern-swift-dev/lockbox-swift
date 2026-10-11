#if canImport(Security)
    #if !os(watchOS) && !os(tvOS) && !os(visionOS)
        import Foundation
        import LocalAuthentication

        public extension LAContext {

            /// The outcome of evaluating a Local Authentication policy or access control.
            enum PolicyEvaluationResult: Sendable {

                /// Evaluation succeeded.
                case success

                /// Evaluation completed without an error but did not authorize the operation.
                case failed

                /// Local Authentication reported an error.
                ///
                /// - Parameter error: The original evaluation error.
                case underlying(any Error)

                /// Converts a Local Authentication callback into a policy evaluation result.
                ///
                /// - Parameters:
                ///   - result: The authorization result returned by Local Authentication.
                ///   - error: The evaluation error, if one occurred.
                /// - Returns: A result preserving errors before mapping the authorization
                ///   Boolean to ``success`` or ``failed``.
                static func from(result: Bool, error: (any Error)?) -> PolicyEvaluationResult {
                    if let error {
                        return .underlying(error)
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
