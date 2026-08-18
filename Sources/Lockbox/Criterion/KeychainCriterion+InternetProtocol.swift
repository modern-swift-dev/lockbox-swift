#if canImport(Security)
import Foundation

public extension KeychainCriterion {

    /// Supported internet protocols for internet-password Keychain items.
    enum InternetProtocol: Sendable {
        /// Hypertext Transfer Protocol.
        case http
        /// Hypertext Transfer Protocol Secure.
        case https
        /// File Transfer Protocol.
        case ftp
        /// File Transfer Protocol Secure.
        case ftps
        /// Server Message Block.
        case smb
        /// Secure Shell.
        case ssh

        /// The Security-framework value used in a Keychain query.
        var queryValue: String {
            switch self {
                case .http:
                    kSecAttrProtocolHTTP as String
                case .https:
                    kSecAttrProtocolHTTPS as String
                case .ftp:
                    kSecAttrProtocolFTP as String
                case .ftps:
                    kSecAttrProtocolFTPS as String
                case .smb:
                    kSecAttrProtocolSMB as String
                case .ssh:
                    kSecAttrProtocolSSH as String
            }
        }
    }
}

#endif
