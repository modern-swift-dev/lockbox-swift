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

            /// A Security-framework protocol value without a named case.
            /// Preserves existing item identities when enumerating the keychain.
            case other(String)

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
                    case let .other(value):
                        value
                }
            }

            /// Converts a Security-framework protocol value without losing unknown values.
            static func from(_ value: String) -> InternetProtocol {
                let protocols: [InternetProtocol] = [.http, .https, .ftp, .ftps, .smb, .ssh]
                for internetProtocol in protocols where internetProtocol.queryValue == value {
                    return internetProtocol
                }
                return .other(value)
            }

            var urlScheme: String? {
                switch self {
                    case .http: "http"
                    case .https: "https"
                    case .ftp: "ftp"
                    case .ftps: "ftps"
                    case .smb: "smb"
                    case .ssh: "ssh"
                    case .other: nil
                }
            }
        }
    }

#endif
