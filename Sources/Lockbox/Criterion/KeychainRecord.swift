#if canImport(Security)
import Foundation

/// A value representation of attributes returned by a Keychain query.
///
/// Construct records from the dictionary returned by the Security framework, or
/// receive them from ``KeychainCriterion/findAll(type:service:accessGroup:accessibility:)``
/// and `retrieve()`. Missing string attributes are represented as empty
/// strings; optional values were absent from the result.
public struct KeychainRecord {

    /// The item's service attribute (`kSecAttrService`), or an empty string when absent.
    public let service: String

    /// The item's account attribute (`kSecAttrAccount`), or an empty string when absent.
    public let account: String

    /// The item's creation date (`kSecAttrCreationDate`), when returned by Keychain Services.
    public let creation: Date?

    /// The item's last modification date (`kSecAttrModificationDate`), when available.
    public let lastUpdate: Date?

    /// The item's description (`kSecAttrDescription`), or an empty string when absent.
    public let description: String

    /// The item's comment (`kSecAttrComment`), or an empty string when absent.
    public let comment: String

    /// The item's label (`kSecAttrLabel`), or an empty string when absent.
    public let label: String

    /// The item's secret data (`kSecValueData`), when requested and returned.
    public let data: Data?

    /// The internet-password protocol value (`kSecAttrProtocol`), when present.
    public let urlScheme: String?

    /// The internet-password server host (`kSecAttrServer`), when present.
    public let urlHost: String?

    /// The internet-password server port (`kSecAttrPort`), when present.
    public let urlPort: Int?

    /// The internet-password path (`kSecAttrPath`), when present.
    public let urlPath: String?

    /// The typed internet-password authentication type, when present.
    public let authenticationType: KeychainCriterion.AuthenticationType?

    /// A URL assembled from the record's internet-password attributes.
    ///
    /// The reconstruction recognizes HTTP explicitly; all other protocol values
    /// are represented with an HTTPS scheme. It returns `nil` when the available
    /// components cannot form a valid URL.
    public var url: URL? {
        var component = URLComponents()
        if urlScheme == (kSecAttrProtocolHTTP as String) {
            component.scheme = "http"
        } else {
            component.scheme = "https"
        }
        component.host = urlHost
        component.port = urlPort
        component.path = urlPath ?? ""
        return component.url
    }

    /// Creates a record from a Security-framework attribute dictionary.
    ///
    /// - Parameter attributes: The dictionary returned by a Keychain query.
    public init(_ attributes: [String: AnyObject]) {
        service = (attributes[kSecAttrService as String] as? String) ?? ""
        account = (attributes[kSecAttrAccount as String] as? String) ?? ""
        creation = attributes[kSecAttrCreationDate as String] as? Date
        lastUpdate = attributes[kSecAttrModificationDate as String] as? Date
        description = (attributes[kSecAttrDescription as String] as? String) ?? ""
        comment = (attributes[kSecAttrComment as String] as? String) ?? ""
        label = (attributes[kSecAttrLabel as String] as? String) ?? ""
        data = (attributes[kSecValueData as String] as? Data)
        urlScheme = attributes[kSecAttrProtocol as String] as? String
        urlHost = attributes[kSecAttrServer as String] as? String
        urlPort = (attributes[kSecAttrPort as String] as? NSNumber)?.intValue
        urlPath = attributes[kSecAttrPath as String] as? String

        if let type = attributes[kSecAttrAuthenticationType as String] as? String {
            authenticationType = KeychainCriterion.AuthenticationType.from(type)
        } else {
            authenticationType = nil
        }
    }
}

#endif
