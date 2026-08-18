#if os(macOS) || os(iOS)
import Foundation
@testable import Lockbox
import Testing

// swiftlint:disable force_unwrapping
@Suite(.serialized) struct QueryBuildingTests {

    @Test func basicQueryContainsSecurityClass() throws {
        let criteria: [KeychainCriterion] = [
            .securityClass(.genericPassword)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecClass as String] as? String == kSecClassGenericPassword as String)
    }

    @Test func queryContainsService() throws {
        let criteria: [KeychainCriterion] = [
            .service("com.test.app")
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrService as String] as? String == "com.test.app")
    }

    @Test func queryContainsAccount() throws {
        let criteria: [KeychainCriterion] = [
            .account("user@example.com")
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrAccount as String] as? String == "user@example.com")
    }

    @Test func queryContainsSynchronizableTrue() throws {
        let criteria: [KeychainCriterion] = [
            .synchronizable(true)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        let syncValue = try #require(query[kSecAttrSynchronizable as String] as? Bool)
        #expect(syncValue)
    }

    @Test func queryContainsSynchronizableFalse() throws {
        let criteria: [KeychainCriterion] = [
            .synchronizable(false)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        let syncValue = try #require(query[kSecAttrSynchronizable as String] as? Bool)
        #expect(!syncValue)
    }

    @Test func queryOmitsSynchronizableWhenNil() throws {
        let criteria: [KeychainCriterion] = [
            .synchronizable(nil)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrSynchronizable as String] == nil)
    }

    @Test func queryContainsAccessGroup() throws {
        let criteria: [KeychainCriterion] = [
            .accessGroup("group.com.test")
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrAccessGroup as String] as? String == "group.com.test")
    }

    @Test func queryContainsLimitOne() throws {
        let criteria: [KeychainCriterion] = [
            .limitOne
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        let limitValue = try #require(query[kSecMatchLimit as String] as? String)
        #expect(limitValue == kSecMatchLimitOne as String)
    }

    @Test func queryContainsLimitAll() throws {
        let criteria: [KeychainCriterion] = [
            .limitAll
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        let limitValue = try #require(query[kSecMatchLimit as String] as? String)
        #expect(limitValue == kSecMatchLimitAll as String)
    }

    @Test func queryContainsReturnAttributesTrue() throws {
        let criteria: [KeychainCriterion] = [
            .returnAttributes(true)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        let attrValue = try #require(query[kSecReturnAttributes as String] as? Bool)
        #expect(attrValue)
    }

    @Test func queryContainsReturnAttributesFalse() throws {
        let criteria: [KeychainCriterion] = [
            .returnAttributes(false)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        let attrValue = try #require(query[kSecReturnAttributes as String] as? Bool)
        #expect(!attrValue)
    }

    @Test func queryContainsReturnDataTrue() throws {
        let criteria: [KeychainCriterion] = [
            .returnData(true)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        let dataValue = try #require(query[kSecReturnData as String] as? Bool)
        #expect(dataValue)
    }

    @Test func queryContainsReturnDataFalse() throws {
        let criteria: [KeychainCriterion] = [
            .returnData(false)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        let dataValue = try #require(query[kSecReturnData as String] as? Bool)
        #expect(!dataValue)
    }

    @Test func queryContainsData() throws {
        let testData = try #require("secret".data(using: .utf8))
        let criteria: [KeychainCriterion] = [
            .data(testData)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecValueData as String] as? Data == testData)
    }

    @Test func queryContainsDescription() throws {
        let criteria: [KeychainCriterion] = [
            .description("Test description")
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrDescription as String] as? String == "Test description")
    }

    @Test func queryContainsLabel() throws {
        let criteria: [KeychainCriterion] = [
            .label("Test label")
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrLabel as String] as? String == "Test label")
    }

    @Test func queryContainsComment() throws {
        let criteria: [KeychainCriterion] = [
            .comment("Test comment")
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrComment as String] as? String == "Test comment")
    }

    @Test func queryContainsAccessibility() throws {
        let criteria: [KeychainCriterion] = [
            .accessible(.whenUnlocked)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        let accessValue = try #require(query[kSecAttrAccessible as String] as? String)
        #expect(accessValue == kSecAttrAccessibleWhenUnlocked as String)
    }

    @Test func queryContainsUrlHost() throws {
        let criteria: [KeychainCriterion] = [
            .urlHost("example.com")
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrServer as String] as? String == "example.com")
    }

    @Test func queryContainsUrlScheme() throws {
        let criteria: [KeychainCriterion] = [
            .urlScheme(.https)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolHTTPS as String)
    }

    @Test func queryContainsUrlPort() throws {
        let criteria: [KeychainCriterion] = [
            .urlPort(8080)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 8080)
    }

    @Test func queryContainsUrlPath() throws {
        let criteria: [KeychainCriterion] = [
            .urlPath("/api/v1")
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrPath as String] as? String == "/api/v1")
    }

    @Test func queryContainsUrlAuthenticationType() throws {
        let criteria: [KeychainCriterion] = [
            .urlAuthenticationType(.httpBasic)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrAuthenticationType as String] as? String == kSecAttrAuthenticationTypeHTTPBasic as String)
    }

    @Test func queryContainsURLWithHTTPS() throws {
        let url = try #require(URL(string: "https://example.com:8443/api"))
        let criteria: [KeychainCriterion] = [
            .url(url, .httpBasic)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])

        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolHTTPS as String)
        #expect(query[kSecAttrServer as String] as? String == "example.com")
        #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 8443)
        #expect(query[kSecAttrPath as String] as? String == "/api")
        #expect(query[kSecAttrAuthenticationType as String] as? String == kSecAttrAuthenticationTypeHTTPBasic as String)
    }

    @Test func queryContainsURLWithHTTP() throws {
        let url = try #require(URL(string: "http://example.com/path"))
        let criteria: [KeychainCriterion] = [
            .url(url)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])

        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolHTTP as String)
        #expect(query[kSecAttrServer as String] as? String == "example.com")
    }

    @Test func queryContainsURLWithFTP() throws {
        let url = try #require(URL(string: "ftp://files.example.com"))
        let criteria: [KeychainCriterion] = [
            .url(url)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])

        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolFTP as String)
    }

    @Test func queryContainsURLWithSSH() throws {
        let url = try #require(URL(string: "ssh://server.example.com"))
        let criteria: [KeychainCriterion] = [
            .url(url)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])

        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolSSH as String)
    }

    @Test func queryOmitsPathForRootURL() throws {
        let url = try #require(URL(string: "https://example.com/"))
        let criteria: [KeychainCriterion] = [
            .url(url)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])

        #expect(query[kSecAttrPath as String] == nil)
    }

    @Test func completeGenericPasswordQuery() throws {
        let criteria: [KeychainCriterion] = [
            .securityClass(.genericPassword),
            .service("com.test.app"),
            .account("user@example.com"),
            .accessible(.whenUnlockedThisDeviceOnly),
            .synchronizable(false)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])

        #expect(query[kSecClass as String] as? String == kSecClassGenericPassword as String)
        #expect(query[kSecAttrService as String] as? String == "com.test.app")
        #expect(query[kSecAttrAccount as String] as? String == "user@example.com")
        let accessValue = try #require(query[kSecAttrAccessible as String] as? String)
        #expect(accessValue == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        let syncValue = try #require(query[kSecAttrSynchronizable as String] as? Bool)
        #expect(!syncValue)
    }

    @Test func completeInternetPasswordQuery() throws {
        let criteria: [KeychainCriterion] = [
            .securityClass(.internetPassword),
            .service("com.test.app"),
            .account("user@example.com"),
            .urlHost("api.example.com"),
            .urlScheme(.https),
            .urlPort(443),
            .urlAuthenticationType(.httpBasic)
        ]
        let query = try #require(criteria.query as? [String: AnyObject])

        #expect(query[kSecClass as String] as? String == kSecClassInternetPassword as String)
        #expect(query[kSecAttrService as String] as? String == "com.test.app")
        #expect(query[kSecAttrAccount as String] as? String == "user@example.com")
        #expect(query[kSecAttrServer as String] as? String == "api.example.com")
        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolHTTPS as String)
        #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 443)
        #expect(query[kSecAttrAuthenticationType as String] as? String == kSecAttrAuthenticationTypeHTTPBasic as String)
    }
}
// swiftlint:enable force_unwrapping
#endif
