#if canImport(Security)
    import Security

    #if canImport(LocalAuthentication) && !os(tvOS)
        import LocalAuthentication
    #endif

    #if canImport(LocalAuthentication) && !os(watchOS) && !os(tvOS) && !os(visionOS)
        import Foundation

        public extension LAContext {

            /// Evaluates access using the strategy selected by a security mode.
            ///
            /// - Parameters:
            ///   - accessControl: The access-control object protecting the keychain item.
            ///   - operation: The keychain operation to authorize.
            ///   - mode: The strategy used to evaluate authentication.
            ///   - localizedReason: The localized explanation shown to the user.
            /// - Returns: The outcome of the authentication evaluation.
            func evaluate(
                accessControl: SecAccessControl,
                operation: LAAccessControlOperation,
                securityMode mode: LAContext.SecurityMode,
                localizedReason: String
            ) async -> PolicyEvaluationResult {
                switch mode {
                    case .highest:
                        await evaluate(accessControl: accessControl, operation: operation, localizedReason: localizedReason)
                    case .normal:
                        await evaluate(policy: .deviceOwnerAuthentication, reason: localizedReason)
                }
            }

            /// Evaluates an access-control object for a keychain operation.
            ///
            /// - Parameters:
            ///   - accessControl: The access-control object protecting the keychain item.
            ///   - operation: The keychain operation to authorize, such as `.useItem` or `.createItem`.
            ///   - localizedReason: The localized explanation shown to the user.
            /// - Returns: The outcome of the authentication evaluation.
            func evaluate(
                accessControl: SecAccessControl,
                operation: LAAccessControlOperation,
                localizedReason: String
            ) async -> PolicyEvaluationResult {
                await withCheckedContinuation { continuation in
                    evaluateAccessControl(accessControl, operation: operation, localizedReason: localizedReason) { result, error in
                        continuation.resume(returning: PolicyEvaluationResult.from(result: result, error: error))
                    }
                }
            }

            /// Evaluates a Local Authentication policy.
            ///
            /// - Parameters:
            ///   - policy: The authentication policy to evaluate.
            ///   - reason: The localized explanation shown to the user.
            /// - Returns: The outcome of the authentication evaluation.
            func evaluate(
                policy: LAPolicy,
                reason: String
            ) async -> PolicyEvaluationResult {
                await withCheckedContinuation { continuation in
                    evaluatePolicy(policy, localizedReason: reason) { result, error in
                        continuation.resume(returning: PolicyEvaluationResult.from(result: result, error: error))
                    }
                }
            }
        }
    #endif

#endif
