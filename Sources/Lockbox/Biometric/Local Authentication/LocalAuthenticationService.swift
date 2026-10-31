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
        public final class LocalAuthenticationService: LocalAuthenticationServiceProtocol, @unchecked Sendable {

            /// The default localized explanation shown in authentication prompts.
            public let reason: String

            /// The localized title of the fallback button, or `nil` for the system default.
            public let fallbackTitle: String?

            /// The localized title of the cancel button, or `nil` for the system default.
            public let cancelTitle: String?

            /// The strategy used when evaluating keychain access.
            public let mode: LAContext.SecurityMode

            /// Guards `currentContext`, which ``invalidate()`` replaces.
            private let lock = NSLock()

            private var currentContext: LAContext

            /// The context shared with Local Authentication and keychain operations.
            ///
            /// ``invalidate()`` replaces this context, so read it for each operation
            /// instead of storing it.
            public var context: LAContext {
                lock.withLock { currentContext }
            }

            /// The biometric authentication technology supported by the device.
            ///
            /// The simulator reports Face ID to support development and testing.
            public var supportedType: LABiometryType {
                #if targetEnvironment(simulator)
                    return .faceID
                #else
                    _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
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
                currentContext = Self.makeContext(reason: reason, fallbackTitle: fallbackTitle, cancelTitle: cancelTitle)
            }

            private static func makeContext(reason: String, fallbackTitle: String?, cancelTitle: String?) -> LAContext {
                let context = LAContext()
                context.localizedReason = reason
                context.localizedFallbackTitle = fallbackTitle
                context.localizedCancelTitle = cancelTitle
                return context
            }

            /// Determines whether the context can evaluate an authentication policy.
            ///
            /// - Parameter policy: The policy whose availability should be checked.
            /// - Returns: `true` when the policy can be evaluated; otherwise, `false`.
            public func isProperlyConfigured(for policy: LAPolicy) -> Bool {
                context.canEvaluatePolicy(policy, error: nil)
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
            ///   - reason: The localized explanation shown to the user, or `nil` to use ``reason``.
            /// - Returns: The outcome of the authentication evaluation.
            public func evaluate(
                policy: LAPolicy = .deviceOwnerAuthentication,
                reason: String?
            ) async -> LAContext.PolicyEvaluationResult {
                await context.evaluate(
                    policy: policy,
                    reason: reason ?? self.reason
                )
            }

            /// Invalidates the current context and replaces it with a new one.
            ///
            /// Any authentication cached by the current context is discarded, and
            /// evaluations already in progress on it are cancelled. Later operations use
            /// the new context, so the service remains usable.
            public func invalidate() {
                let replacement = Self.makeContext(reason: reason, fallbackTitle: fallbackTitle, cancelTitle: cancelTitle)
                let invalidated = lock.withLock {
                    let previous = currentContext
                    currentContext = replacement
                    return previous
                }
                invalidated.invalidate()
            }
        }
    #endif

#endif
