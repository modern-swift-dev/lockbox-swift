#if os(macOS) || os(iOS)
import Foundation
@testable import Lockbox
import Testing

@Suite(.serialized) struct KeychainRecordTests {

    // MARK: - Basic Attribute Parsing

    @Test func initWithEmptyDictionaryUsesDefaults() {
        let record = KeychainRecord([:])

        #expect(record.service == "")
        #expect(record.account == "")
        #expect(record.creation == nil)
        #expect(record.lastUpdate == nil)
        #expect(record.description == "")
        #expect(record.comment == "")
        #expect(record.label == "")
        #expect(record.data == nil)
        #expect(record.urlScheme == nil)
        #expect(record.urlHost == nil)
        #expect(record.urlPort == nil)
        #expect(record.urlPath == nil)
        #expect(record.authenticationType == nil)
    }

    @Test func initParsesService() {
        let attributes: [String: AnyObject] = [
            kSecAttrService as String: "com.test.service" as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.service == "com.test.service")
    }

    @Test func initParsesAccount() {
        let attributes: [String: AnyObject] = [
            kSecAttrAccount as String: "user@example.com" as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.account == "user@example.com")
    }

    @Test func initParsesCreationDate() {
        let creationDate = Date(timeIntervalSince1970: 1_700_000_000)
        let attributes: [String: AnyObject] = [
            kSecAttrCreationDate as String: creationDate as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.creation == creationDate)
    }

    @Test func initParsesLastUpdateDate() {
        let lastUpdate = Date(timeIntervalSince1970: 1_700_100_000)
        let attributes: [String: AnyObject] = [
            kSecAttrModificationDate as String: lastUpdate as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.lastUpdate == lastUpdate)
    }

    @Test func initParsesDescription() {
        let attributes: [String: AnyObject] = [
            kSecAttrDescription as String: "Test Description" as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.description == "Test Description")
    }

    @Test func initParsesComment() {
        let attributes: [String: AnyObject] = [
            kSecAttrComment as String: "Test Comment" as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.comment == "Test Comment")
    }

    @Test func initParsesLabel() {
        let attributes: [String: AnyObject] = [
            kSecAttrLabel as String: "Test Label" as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.label == "Test Label")
    }

    @Test func initParsesData() throws {
        let testData = try #require("secret password".data(using: .utf8))
        let attributes: [String: AnyObject] = [
            kSecValueData as String: testData as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.data == testData)
    }

    // MARK: - URL Attribute Parsing

    @Test func initParsesUrlScheme() {
        let attributes: [String: AnyObject] = [
            kSecAttrProtocol as String: (kSecAttrProtocolHTTPS as String) as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.urlScheme == kSecAttrProtocolHTTPS as String)
    }

    @Test func initParsesUrlHost() {
        let attributes: [String: AnyObject] = [
            kSecAttrServer as String: "api.example.com" as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.urlHost == "api.example.com")
    }

    @Test func initParsesUrlPort() {
        let attributes: [String: AnyObject] = [
            kSecAttrPort as String: NSNumber(value: 8080) as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.urlPort == 8080)
    }

    @Test func initParsesUrlPath() {
        let attributes: [String: AnyObject] = [
            kSecAttrPath as String: "/api/v1/users" as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.urlPath == "/api/v1/users")
    }

    // MARK: - Authentication Type Parsing

    @Test func initParsesAuthenticationTypeNTLM() {
        let attributes: [String: AnyObject] = [
            kSecAttrAuthenticationType as String: (kSecAttrAuthenticationTypeNTLM as String) as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.authenticationType?.queryValue == KeychainCriterion.AuthenticationType.ntlm.queryValue)
    }

    @Test func initParsesAuthenticationTypeHTTPBasic() {
        let attributes: [String: AnyObject] = [
            kSecAttrAuthenticationType as String: (kSecAttrAuthenticationTypeHTTPBasic as String) as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.authenticationType?.queryValue == KeychainCriterion.AuthenticationType.httpBasic.queryValue)
    }

    @Test func initParsesAuthenticationTypeHTMLForm() {
        let attributes: [String: AnyObject] = [
            kSecAttrAuthenticationType as String: (kSecAttrAuthenticationTypeHTMLForm as String) as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.authenticationType?.queryValue == KeychainCriterion.AuthenticationType.htmlForm.queryValue)
    }

    // MARK: - URL Computed Property

    @Test func urlPropertyReturnsHTTPSForUnknownScheme() {
        let attributes: [String: AnyObject] = [
            kSecAttrServer as String: "example.com" as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.url?.scheme == "https")
        #expect(record.url?.host == "example.com")
    }

    @Test func urlPropertyReturnsHTTPForHTTPScheme() {
        let attributes: [String: AnyObject] = [
            kSecAttrProtocol as String: (kSecAttrProtocolHTTP as String) as AnyObject,
            kSecAttrServer as String: "example.com" as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.url?.scheme == "http")
        #expect(record.url?.host == "example.com")
    }

    @Test func urlPropertyIncludesPort() {
        let attributes: [String: AnyObject] = [
            kSecAttrServer as String: "example.com" as AnyObject,
            kSecAttrPort as String: NSNumber(value: 8443) as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.url?.port == 8443)
    }

    @Test func urlPropertyIncludesPath() {
        let attributes: [String: AnyObject] = [
            kSecAttrServer as String: "example.com" as AnyObject,
            kSecAttrPath as String: "/api/auth" as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.url?.path == "/api/auth")
    }

    @Test func urlPropertyWithEmptyPath() {
        let attributes: [String: AnyObject] = [
            kSecAttrServer as String: "example.com" as AnyObject
        ]
        let record = KeychainRecord(attributes)

        #expect(record.url?.path == "")
    }

    @Test func urlPropertyBuildsCompleteURL() {
        let attributes: [String: AnyObject] = [
            kSecAttrProtocol as String: (kSecAttrProtocolHTTPS as String) as AnyObject,
            kSecAttrServer as String: "api.example.com" as AnyObject,
            kSecAttrPort as String: NSNumber(value: 8443) as AnyObject,
            kSecAttrPath as String: "/v1/auth" as AnyObject
        ]
        let record = KeychainRecord(attributes)
        let url = record.url

        #expect(url?.scheme == "https")
        #expect(url?.host == "api.example.com")
        #expect(url?.port == 8443)
        #expect(url?.path == "/v1/auth")
    }

    // MARK: - Complete Record Parsing

    @Test func initParsesCompleteGenericPasswordAttributes() throws {
        let creationDate = Date(timeIntervalSince1970: 1_700_000_000)
        let modificationDate = Date(timeIntervalSince1970: 1_700_100_000)
        let secretData = try #require("mySecretPassword123".data(using: .utf8))

        let attributes: [String: AnyObject] = [
            kSecAttrService as String: "com.myapp.auth" as AnyObject,
            kSecAttrAccount as String: "john.doe@example.com" as AnyObject,
            kSecAttrCreationDate as String: creationDate as AnyObject,
            kSecAttrModificationDate as String: modificationDate as AnyObject,
            kSecAttrDescription as String: "User login credentials" as AnyObject,
            kSecAttrComment as String: "Primary account" as AnyObject,
            kSecAttrLabel as String: "MyApp Login" as AnyObject,
            kSecValueData as String: secretData as AnyObject
        ]

        let record = KeychainRecord(attributes)

        #expect(record.service == "com.myapp.auth")
        #expect(record.account == "john.doe@example.com")
        #expect(record.creation == creationDate)
        #expect(record.lastUpdate == modificationDate)
        #expect(record.description == "User login credentials")
        #expect(record.comment == "Primary account")
        #expect(record.label == "MyApp Login")
        #expect(record.data == secretData)
    }

    @Test func initParsesCompleteInternetPasswordAttributes() throws {
        let secretData = try #require("api_token_xyz".data(using: .utf8))

        let attributes: [String: AnyObject] = [
            kSecAttrService as String: "com.myapp.api" as AnyObject,
            kSecAttrAccount as String: "api_user" as AnyObject,
            kSecAttrProtocol as String: (kSecAttrProtocolHTTPS as String) as AnyObject,
            kSecAttrServer as String: "api.service.com" as AnyObject,
            kSecAttrPort as String: NSNumber(value: 443) as AnyObject,
            kSecAttrPath as String: "/oauth/token" as AnyObject,
            kSecAttrAuthenticationType as String: (kSecAttrAuthenticationTypeHTTPBasic as String) as AnyObject,
            kSecValueData as String: secretData as AnyObject
        ]

        let record = KeychainRecord(attributes)

        #expect(record.service == "com.myapp.api")
        #expect(record.account == "api_user")
        #expect(record.urlScheme == kSecAttrProtocolHTTPS as String)
        #expect(record.urlHost == "api.service.com")
        #expect(record.urlPort == 443)
        #expect(record.urlPath == "/oauth/token")
        #expect(record.authenticationType?.queryValue == KeychainCriterion.AuthenticationType.httpBasic.queryValue)
        #expect(record.data == secretData)

        let url = record.url
        #expect(url?.absoluteString == "https://api.service.com:443/oauth/token")
    }
}
#endif
