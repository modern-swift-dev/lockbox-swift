#if os(macOS) || os(iOS)
    import Foundation
    @testable import Lockbox
    import Testing

    @Suite(.serialized) struct QueryBuildingURLTests {

        @Test func queryContainsURLWithSFTPHasNoProtocol() throws {
            let url = try #require(URL(string: "sftp://files.example.com/path"))
            let criteria: [KeychainCriterion] = [
                .url(url)
            ]
            let query = try #require(criteria.query as? [String: AnyObject])

            // SFTP runs over SSH, so it must not be recorded as FTPS.
            #expect(query[kSecAttrProtocol as String] == nil)
            #expect(query[kSecAttrServer as String] as? String == "files.example.com")
        }

        @Test func urlHostIsLowercased() throws {
            let mixedCase = try #require(URL(string: "https://Example.COM/Login"))
            let lowercase = try #require(URL(string: "https://example.com/Login"))

            let query = try #require([KeychainCriterion.url(mixedCase)].query as? [String: AnyObject])
            let lowercaseQuery = try #require([KeychainCriterion.url(lowercase)].query as? [String: AnyObject])

            #expect(query[kSecAttrServer as String] as? String == "example.com")
            #expect(query[kSecAttrPath as String] as? String == "/Login")
            #expect(query as NSDictionary == lowercaseQuery as NSDictionary)
        }

        @Test func internetPasswordHostIsLowercased() throws {
            let url = try #require(URL(string: "https://API.Example.com"))
            let password = KeychainPassword.internet(url: url, account: "user")

            let query = try #require(password.criteria.query as? [String: AnyObject])
            #expect(query[kSecAttrServer as String] as? String == "api.example.com")
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

            #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolSMB as String)
            let explicitQuery = try #require([KeychainCriterion.urlScheme(.smb)].query as? [String: AnyObject])
            #expect(query[kSecAttrProtocol as String] as? String == explicitQuery[kSecAttrProtocol as String] as? String)
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

            // Empty path is stored as the root path, like KeychainPassword.internet
            #expect(query[kSecAttrPath as String] as? String == "/")
            #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 443)
        }

        @Test(arguments: [
            "https://example.com",
            "http://example.com:8080/login",
            "example.com",
            "ftp://files.example.com/pub",
            "ssh://host.example.com:2222",
            "smb://server.local/share",
            "sftp://files.example.com/path",
            "custom://server.example.com:9000/path"
        ])
        func urlCriterionMatchesInternetPasswordAttributes(string: String) throws {
            let url = try #require(URL(string: string))
            let urlQuery = try #require([KeychainCriterion.url(url, .httpBasic)].query as? [String: AnyObject])
            let password = KeychainPassword.internet(
                url: url,
                authenticationType: .httpBasic,
                account: "user"
            )
            let passwordQuery = try #require(password.criteria.query as? [String: AnyObject])

            for key in [kSecAttrProtocol, kSecAttrPort, kSecAttrServer, kSecAttrPath, kSecAttrAuthenticationType] {
                #expect(urlQuery[key as String] as? NSObject == passwordQuery[key as String] as? NSObject, "\(key)")
            }
        }

        @Test(arguments: [
            "https://example.com",
            "http://example.com:8080/login",
            "ftp://files.example.com/pub",
            "ssh://host.example.com:2222",
            "custom://server.example.com:9000/path"
        ])
        func urlCriterionAndInternetPasswordAgreeByDefault(string: String) throws {
            let url = try #require(URL(string: string))
            let urlQuery = try #require([KeychainCriterion.url(url)].query as? [String: AnyObject])
            let password = KeychainPassword.internet(url: url, account: "user")
            let passwordQuery = try #require(password.criteria.query as? [String: AnyObject])

            for key in [kSecAttrProtocol, kSecAttrPort, kSecAttrServer, kSecAttrPath, kSecAttrAuthenticationType] {
                #expect(urlQuery[key as String] as? NSObject == passwordQuery[key as String] as? NSObject, "\(key)")
            }
            let defaultType = kSecAttrAuthenticationTypeDefault as String
            #expect(urlQuery[kSecAttrAuthenticationType as String] as? String == defaultType)
            #expect(passwordQuery[kSecAttrAuthenticationType as String] as? String == defaultType)
        }

        @Test func urlWithExplicitPortKeepsPortForNonHTTPSchemes() throws {
            let url = try #require(URL(string: "ssh://host.example.com:2222"))
            let query = try #require([KeychainCriterion.url(url)].query as? [String: AnyObject])

            #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolSSH as String)
            #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 2222)
        }

        @Test func urlWithoutPortHasNoDefaultPortForNonHTTPSchemes() throws {
            let url = try #require(URL(string: "ftp://files.example.com"))
            let query = try #require([KeychainCriterion.url(url)].query as? [String: AnyObject])

            #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolFTP as String)
            #expect(query[kSecAttrPort as String] == nil)
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
