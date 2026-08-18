#if canImport(Security)
import Foundation

public extension KeychainCriterion {

    /// Keychain item classes supported by the Security framework.
    enum SecurityClass: Sendable {

        /// A generic-password item (`kSecClassGenericPassword`).
        case genericPassword

        /// An internet-password item (`kSecClassInternetPassword`).
        case internetPassword

        /// A certificate item (`kSecClassCertificate`).
        case certificate

        /// A cryptographic key item (`kSecClassKey`).
        case key

        /// An identity item (`kSecClassIdentity`).
        case identity

        /// The Security-framework value used in a Keychain query.
        var queryValue: String {
            switch self {
                case .genericPassword:
                    kSecClassGenericPassword as String
                case .internetPassword:
                    kSecClassInternetPassword as String
                case .certificate:
                    kSecClassCertificate as String
                case .key:
                    kSecClassKey as String
                case .identity:
                    kSecClassIdentity as String
            }
        }
    }
}

#endif
