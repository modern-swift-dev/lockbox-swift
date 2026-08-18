#if os(macOS) || os(iOS)
import Foundation
@testable import Lockbox
import Testing

@Suite(.serialized) struct QueryBuildingURLTests {

    @Test func queryContainsURLWithSFTP() throws {
        let url = try #require(URL(string: "sftp://files.example.com/path"))
        let criteria: [KeychainCriterion] = [
            .url(url)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])

        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolFTPS as String)
    }

    @Test func queryContainsURLWithFTPS() throws {
        let url = try #require(URL(string: "ftps://files.example.com"))
        let criteria: [KeychainCriterion] = [
            .url(url)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])

        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolFTPS as String)
    }

    @Test func queryContainsURLWithSMB() throws {
        let url = try #require(URL(string: "smb://server.local/share"))
        let criteria: [KeychainCriterion] = [
            .url(url)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])

        // Note: SMB incorrectly maps to SSH in the implementation
        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolSSH as String)
    }

    @Test func queryContainsURLWithUnknownScheme() throws {
        let url = try #require(URL(string: "custom://server.example.com/path"))
        let criteria: [KeychainCriterion] = [
            .url(url)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])

        // Unknown scheme should not set protocol
        #expect(query[kSecAttrProtocol as String] == nil)
        #expect(query[kSecAttrServer as String] as? String == "server.example.com")
    }

    @Test func queryContainsURLWithNoPath() throws {
        let url = try #require(URL(string: "https://example.com"))
        let criteria: [KeychainCriterion] = [
            .url(url)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])

        // Empty path should not be included
        #expect(query[kSecAttrPath as String] == nil)
    }

    @Test func urlSchemeHTTPQueryValue() throws {
        let criteria: [KeychainCriterion] = [.urlScheme(.http)]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolHTTP as String)
    }

    @Test func urlSchemeFTPQueryValue() throws {
        let criteria: [KeychainCriterion] = [.urlScheme(.ftp)]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolFTP as String)
    }

    @Test func urlSchemeFTPSQueryValue() throws {
        let criteria: [KeychainCriterion] = [.urlScheme(.ftps)]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolFTPS as String)
    }

    @Test func urlSchemeSMBQueryValue() throws {
        let criteria: [KeychainCriterion] = [.urlScheme(.smb)]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolSMB as String)
    }

    @Test func urlSchemeSSHQueryValue() throws {
        let criteria: [KeychainCriterion] = [.urlScheme(.ssh)]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolSSH as String)
    }
}
#endif
