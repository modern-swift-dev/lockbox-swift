#if canImport(Security)
    import Foundation
    #if canImport(LocalAuthentication)
        import LocalAuthentication
    #endif
    @testable import Lockbox
    import Testing

    @Suite(.serialized) struct KeychainInternetPasswordTests {

        @Test(.requiresKeychain, arguments: [KeychainCriterion.InternetProtocol.ftp, .other(kSecAttrProtocolIMAP as String)])
        func listedHandleReadsUpdatesAndDeletesOriginalItem(internetProtocol: KeychainCriterion.InternetProtocol) throws {
            let service = "LockboxTests.enumeration.\(UUID().uuidString)"
            let account = UUID().uuidString
            let criteria: [KeychainCriterion] = [
                .securityClass(.internetPassword),
                .securityDomain(service),
                .account(account),
                .urlHost("example.invalid"),
                .urlScheme(internetProtocol),
                .urlAuthenticationType(.default),
                .urlPort(0),
                .urlPath("")
            ]
            defer { try? criteria.delete() }
            try criteria.create(data: Data("original".utf8))
            let handles = try KeychainPassword.allInternetPassword(securityDomain: service)
            let handle = try #require(handles.first {
                let query = $0.criteria.query as NSDictionary
                return query[kSecAttrAccount as String] as? String == account
            })
            #expect(try handle.getString() == "original")
            try handle.set(string: "updated")
            #expect(try criteria.retrieve()?.data == Data("updated".utf8))
            try handle.remove()
            #expect(try !criteria.exists())
        }

        private let testDomain = "com.slkeychain.internet.\(UUID().uuidString)"

        private func cleanup(securityDomain: String, account: String, url: URL) {
            let password = KeychainPassword.internet(url: url, securityDomain: securityDomain, account: account)
            try? password.remove()
        }

        @Test func internetPasswordCreationWithHTTPS() throws {
            let url = try #require(URL(string: "https://api.example.com/auth"))
            let account = "test_\(UUID().uuidString)"
            let password = KeychainPassword.internet(url: url, securityDomain: testDomain, account: account)

            #expect(!password.criteria.isEmpty)

            let query = try #require(password.criteria.query as? [String: AnyObject])
            #expect(query[kSecClass as String] as? String == kSecClassInternetPassword as String)
            // Internet passwords have no service attribute; iOS rejects it.
            #expect(query[kSecAttrService as String] == nil)
            #expect(query[kSecAttrSecurityDomain as String] as? String == testDomain)
            #expect(query[kSecAttrAccount as String] as? String == account)
            #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolHTTPS as String)
            #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 443)
            #expect(query[kSecAttrServer as String] as? String == "api.example.com")
            #expect(query[kSecAttrPath as String] as? String == "/auth")
        }

        @Test func internetPasswordCreationWithHTTP() throws {
            let url = try #require(URL(string: "http://example.com/login"))
            let account = "test_\(UUID().uuidString)"
            let password = KeychainPassword.internet(url: url, securityDomain: testDomain, account: account)

            let query = try #require(password.criteria.query as? [String: AnyObject])
            #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolHTTP as String)
            #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 80)
        }

        @Test func internetPasswordCreationWithCustomPort() throws {
            let url = try #require(URL(string: "https://api.example.com:8443/auth"))
            let account = "test_\(UUID().uuidString)"
            let password = KeychainPassword.internet(url: url, securityDomain: testDomain, account: account)

            let query = try #require(password.criteria.query as? [String: AnyObject])
            #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 8443)
        }

        @Test func internetPasswordCreationWithNilSchemeDefaultsToHTTPS() throws {
            var components = URLComponents()
            components.host = "api.example.com"
            components.path = "/auth"
            let url = try #require(components.url)
            let account = "test_\(UUID().uuidString)"
            let password = KeychainPassword.internet(url: url, securityDomain: testDomain, account: account)

            let query = try #require(password.criteria.query as? [String: AnyObject])
            #expect(query[kSecAttrProtocol as String] as? String == kSecAttrProtocolHTTPS as String)
            #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == 443)
            #expect(query[kSecAttrServer as String] as? String == "api.example.com")
            #expect(query[kSecAttrPath as String] as? String == "/auth")
        }

        @Test func internetPasswordCreationWithRootPathUsesSlash() throws {
            let url = try #require(URL(string: "https://api.example.com"))
            let account = "test_\(UUID().uuidString)"
            let password = KeychainPassword.internet(url: url, securityDomain: testDomain, account: account)

            let query = try #require(password.criteria.query as? [String: AnyObject])
            #expect(query[kSecAttrPath as String] as? String == "/")
        }

        @Test func internetPasswordCreationWithUnknownSchemeOmitsProtocolAndPort() throws {
            let url = try #require(URL(string: "custom://api.example.com/auth"))
            let account = "test_\(UUID().uuidString)"
            let password = KeychainPassword.internet(
                url: url,
                authenticationType: .httpBasic,
                securityDomain: testDomain,
                account: account
            )

            let query = try #require(password.criteria.query as? [String: AnyObject])
            #expect(query[kSecAttrProtocol as String] == nil)
            #expect(query[kSecAttrPort as String] == nil)
            #expect(query[kSecAttrServer as String] as? String == "api.example.com")
            #expect(query[kSecAttrPath as String] as? String == "/auth")
            #expect(query[kSecAttrAuthenticationType as String] as? String == kSecAttrAuthenticationTypeHTTPBasic as String)
        }

        #if canImport(LocalAuthentication) && !os(tvOS)
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
                    securityDomain: testDomain,
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
                #expect(query[kSecAttrAccessControl as String] == nil)
                #expect(query[kSecUseAuthenticationContext as String] is LAContext)
                let createQuery = try #require(password.createCriteria.query as? [String: AnyObject])
                #expect(createQuery[kSecAttrAccessControl as String] != nil)
            }
        #endif

        @Test(.requiresKeychain) func internetPasswordSetAndGet() throws {
            let url = try #require(URL(string: "https://api.test.com/auth"))
            let account = "inet_test_\(UUID().uuidString)"
            let password = KeychainPassword.internet(url: url, securityDomain: testDomain, account: account)

            defer { cleanup(securityDomain: testDomain, account: account, url: url) }

            try password.set(string: "myInternetPassword")
            let retrieved = try password.getString()

            #expect(retrieved == "myInternetPassword")
        }

        @Test(.requiresKeychain) func internetPasswordUpdate() throws {
            let url = try #require(URL(string: "https://api.test.com/auth"))
            let account = "inet_update_\(UUID().uuidString)"
            let password = KeychainPassword.internet(url: url, securityDomain: testDomain, account: account)

            defer { cleanup(securityDomain: testDomain, account: account, url: url) }

            try password.set(string: "initial")
            try password.set(string: "updated")
            let retrieved = try password.getString()

            #expect(retrieved == "updated")
        }

        @Test(.requiresKeychain) func internetPasswordRemove() throws {
            let url = try #require(URL(string: "https://api.test.com/auth"))
            let account = "inet_remove_\(UUID().uuidString)"
            let password = KeychainPassword.internet(url: url, securityDomain: testDomain, account: account)

            try password.set(string: "toBeRemoved")
            try password.remove()

            let retrieved = try password.getString()
            #expect(retrieved == nil)
        }
    }

#endif
