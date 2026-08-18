#if canImport(Security)
#if !os(watchOS) && !os(tvOS) && !os(visionOS)
import Foundation
import LocalAuthentication

public extension LAContext {

    /// The level of Local Authentication protection used for keychain operations.
    enum SecurityMode: Sendable {

        /// Evaluates the keychain item's `SecAccessControl` requirements directly.
        case highest

        /// Evaluates device-owner authentication without binding evaluation to the
        /// keychain item's access-control object.
        case normal

        /// Adapts a security mode for the current execution environment.
        ///
        /// The simulator always uses ``normal`` because direct access-control
        /// evaluation isn't available there. A physical device returns `value`.
        ///
        /// - Parameter value: The mode to use on a physical device.
        /// - Returns: ``normal`` on the simulator; otherwise, `value`.
        public static func adapt(_ value: SecurityMode = .highest) -> SecurityMode {
            #if targetEnvironment(simulator)
            return .normal
            #else
            return value
            #endif
        }
    }

}
#endif

#endif
