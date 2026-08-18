#if canImport(Security)
#if os(macOS)
import Foundation
import LocalAuthentication
@testable import Lockbox
import Testing

/// Error code for missing entitlements (common in test environments)
private let errSecMissingEntitlement: OSStatus = -34018

/// Checks if the keychain is accessible (has proper entitlements)
private func isKeychainAccessible() -> Bool {
    let testCriteria: [KeychainCriterion] = [
        .securityClass(.genericPassword),
        .service("com.slkeychain.entitlement.check"),
        .account("test")
    ]
    do {
        _ = try testCriteria.exists()
        return true
    } catch let error as KeychainError {
        if case let .underlyingError(status, _) = error, status == errSecMissingEntitlement {
            return false
        }
        return true
    } catch {
        return true
    }
}

@Suite(.serialized) struct KeychainInternetPasswordTests {

    private let testService = "com.slkeychain.internet.\(UUID().uuidString)"

    private func cleanup(service: String, account: String, url: URL) {
        let password = KeychainPassword.internet(url: url, service: service, account: account)
        try? password.remove()
    }

    private func skipIfNoKeychainAccess() throws {
        try #require(isKeychainAccessible(), "Keychain access not available (missing entitlements)")
    }

    @Test func internetPasswordCreationWithHTTPS() throws {
        let url = try #require(URL(string: "https://api.example.com/auth"))
        let account = "test_\(UUID().uuidString)"
        let password = KeychainPassword.internet(url: url, service: testService, account: account)

        #expect(!password.criteria.isEmpty)

        let query = try #require(password.criteria.query as? [String: AnyObject])
        #expect(query[kSecClass as String] as? String == kSecClassInternetPassword as String)
        #expect(query[kSecAttrService as String] as? String == testService)
        #expect(query[kSecAttrAccount as String] as? String == account)
        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolHTTPS as String)
        #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 443)
        #expect(query[kSecAttrServer as String] as? String == "api.example.com")
        #expect(query[kSecAttrPath as String] as? String == "/auth")
    }

    @Test func internetPasswordCreationWithHTTP() throws {
        let url = try #require(URL(string: "http://example.com/login"))
        let account = "test_\(UUID().uuidString)"
        let password = KeychainPassword.internet(url: url, service: testService, account: account)

        let query = try #require(password.criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolHTTP as String)
        #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 80)
    }

    @Test func internetPasswordCreationWithCustomPort() throws {
        let url = try #require(URL(string: "https://api.example.com:8443/auth"))
        let account = "test_\(UUID().uuidString)"
        let password = KeychainPassword.internet(url: url, service: testService, account: account)

        let query = try #require(password.criteria.query as? [String: AnyObject])
        #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 8443)
    }

    @Test func internetPasswordCreationWithNilSchemeDefaultsToHTTPS() throws {
        var components = URLComponents()
        components.host = "api.example.com"
        components.path = "/auth"
        let url = try #require(components.url)
        let account = "test_\(UUID().uuidString)"
        let password = KeychainPassword.internet(url: url, service: testService, account: account)

        let query = try #require(password.criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolHTTPS as String)
        #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 443)
        #expect(query[kSecAttrServer as String] as? String == "api.example.com")
        #expect(query[kSecAttrPath as String] as? String == "/auth")
    }

    @Test func internetPasswordCreationWithRootPathUsesSlash() throws {
        let url = try #require(URL(string: "https://api.example.com"))
        let account = "test_\(UUID().uuidString)"
        let password = KeychainPassword.internet(url: url, service: testService, account: account)

        let query = try #require(password.criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrPath as String] as? String == "/")
    }

    @Test func internetPasswordCreationWithUnknownSchemeOmitsProtocolAndPort() throws {
        let url = try #require(URL(string: "custom://api.example.com/auth"))
        let account = "test_\(UUID().uuidString)"
        let password = KeychainPassword.internet(
            url: url,
            authenticationType: .httpBasic,
            service: testService,
            account: account
        )

        let query = try #require(password.criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrProtocol as String] == nil)
        #expect(query[kSecAttrPort as String] == nil)
        #expect(query[kSecAttrServer as String] as? String == "api.example.com")
        #expect(query[kSecAttrPath as String] as? String == "/auth")
        #expect(query[kSecAttrAuthenticationType as String] as? String == kSecAttrAuthenticationTypeHTTPBasic as String)
    }

    @Test func internetPasswordCreationWithSecurityOptionsAddsQueryKeys() throws {
        let url = try #require(URL(string: "https://api.example.com/auth"))
        let account = "test_\(UUID().uuidString)"
        let accessGroup = "ABC123.com.example.shared"
        var error: Unmanaged<CFError>?
        let accessControl = try #require(SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &error
        ))
        let password = KeychainPassword.internet(
            url: url,
            authenticationType: .httpDigest,
            service: testService,
            account: account,
            accessGroup: accessGroup,
            synchronizable: true,
            accessControl: accessControl,
            contextProvider: { LAContext() }
        )

        let query = try #require(password.criteria.query as? [String: AnyObject])
        #expect(query[kSecAttrAccessGroup as String] as? String == accessGroup)
        let synchronizable = try #require(query[kSecAttrSynchronizable as String] as? Bool)
        #expect(synchronizable)
        #expect(query[kSecAttrAuthenticationType as String] as? String == kSecAttrAuthenticationTypeHTTPDigest as String)
        #expect(query[kSecAttrAccessControl as String] != nil)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
    }

    @Test func internetPasswordSetAndGet() throws {
        try skipIfNoKeychainAccess()
        let url = try #require(URL(string: "https://api.test.com/auth"))
        let account = "inet_test_\(UUID().uuidString)"
        let password = KeychainPassword.internet(url: url, service: testService, account: account)

        defer { cleanup(service: testService, account: account, url: url) }

        try password.set(string: "myInternetPassword")
        let retrieved = try password.getString()

        #expect(retrieved == "myInternetPassword")
    }

    @Test func internetPasswordUpdate() throws {
        try skipIfNoKeychainAccess()
        let url = try #require(URL(string: "https://api.test.com/auth"))
        let account = "inet_update_\(UUID().uuidString)"
        let password = KeychainPassword.internet(url: url, service: testService, account: account)

        defer { cleanup(service: testService, account: account, url: url) }

        try password.set(string: "initial")
        try password.set(string: "updated")
        let retrieved = try password.getString()

        #expect(retrieved == "updated")
    }

    @Test func internetPasswordRemove() throws {
        try skipIfNoKeychainAccess()
        let url = try #require(URL(string: "https://api.test.com/auth"))
        let account = "inet_remove_\(UUID().uuidString)"
        let password = KeychainPassword.internet(url: url, service: testService, account: account)

        try password.set(string: "toBeRemoved")
        try password.remove()

        let retrieved = try password.getString()
        #expect(retrieved == nil)
    }
}
#endif

#endif
