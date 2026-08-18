#if canImport(Security)
import Foundation

public extension KeychainCriterion {
    /// Authentication mechanisms for internet-password Keychain items.
    enum AuthenticationType: Sendable {
        /// NTLM authentication.
        case ntlm
        /// Microsoft Network authentication.
        case msn
        /// Distributed Password Authentication.
        case dpa
        /// Remote Password Authentication.
        case rpa
        /// HTTP Basic authentication.
        case httpBasic
        /// HTTP Digest authentication.
        case httpDigest
        /// HTML form authentication.
        case htmlForm
        /// The Security framework's default authentication type.
        case `default`

        /// The Security-framework value used in a Keychain query.
        var queryValue: String {
            switch self {
                case .ntlm: kSecAttrAuthenticationTypeNTLM as String
                case .msn: kSecAttrAuthenticationTypeMSN as String
                case .dpa: kSecAttrAuthenticationTypeDPA as String
                case .rpa: kSecAttrAuthenticationTypeRPA as String
                case .httpBasic: kSecAttrAuthenticationTypeHTTPBasic as String
                case .httpDigest: kSecAttrAuthenticationTypeHTTPDigest as String
                case .htmlForm: kSecAttrAuthenticationTypeHTMLForm as String
                case .default: kSecAttrAuthenticationTypeDefault as String
            }
        }

        /// Converts a Security-framework authentication-type value to its typed equivalent.
        ///
        /// - Parameter value: A value returned in `kSecAttrAuthenticationType`.
        /// - Returns: The matching type, or ``KeychainCriterion/AuthenticationType/default``
        ///   when the value is unknown.
        static func from(_ value: String) -> AuthenticationType {

            if value == kSecAttrAuthenticationTypeNTLM as String {
                return .ntlm
            }
            if value == kSecAttrAuthenticationTypeMSN as String {
                return .msn
            }
            if value == kSecAttrAuthenticationTypeDPA as String {
                return .dpa
            }
            if value == kSecAttrAuthenticationTypeRPA as String {
                return .rpa
            }
            if value == kSecAttrAuthenticationTypeHTTPBasic as String {
                return .httpBasic
            }
            if value == kSecAttrAuthenticationTypeHTTPDigest as String {
                return .httpDigest
            }
            if value == kSecAttrAuthenticationTypeHTMLForm as String {
                return .htmlForm
            }
            if value == kSecAttrAuthenticationTypeDefault as String {
                return .default
            }

            return .default
        }

    }
}

#endif
