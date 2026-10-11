#if canImport(Security)
    import Foundation
    @testable import Lockbox
    import Testing

    struct ValueConformanceTests {

        private func requireSendable(_: (some Sendable).Type) {}

        @Test func valueTypesAreSendable() {
            requireSendable(KeychainRecord.self)
            requireSendable(KeychainError.self)
            requireSendable(BiometricServiceResult.self)
            requireSendable(KeychainCriterion.AuthenticationType.self)
            requireSendable(KeychainCriterion.InternetProtocol.self)
        }

        @Test func recordsWithSameAttributesAreEqual() {
            let attributes: [String: AnyObject] = [
                kSecAttrService as String: "service" as NSString,
                kSecAttrAccount as String: "account" as NSString,
                kSecAttrAuthenticationType as String: kSecAttrAuthenticationTypeHTTPBasic,
                kSecValueData as String: Data("secret".utf8) as NSData
            ]

            #expect(KeychainRecord(attributes) == KeychainRecord(attributes))
            #expect(Set([KeychainRecord(attributes), KeychainRecord(attributes)]).count == 1)
        }

        @Test func recordsWithDifferentAttributesAreNotEqual() {
            let first = KeychainRecord([kSecAttrAccount as String: "first" as NSString])
            let second = KeychainRecord([kSecAttrAccount as String: "second" as NSString])

            #expect(first != second)
        }

        @Test func biometricResultsCompareByCaseAndCredentials() {
            #expect(BiometricServiceResult.success(username: "user", password: "secret")
                == .success(username: "user", password: "secret"))
            #expect(BiometricServiceResult.success(username: "user", password: "secret")
                != .biometricChanged(username: "user", password: "secret"))
            #expect(BiometricServiceResult.success(username: "user", password: "secret")
                != .success(username: "user", password: "other"))
        }

        @Test func criterionValuesCompareByValue() {
            #expect(KeychainCriterion.AuthenticationType.other("custom") == .other("custom"))
            #expect(KeychainCriterion.AuthenticationType.httpBasic != .httpDigest)
            #expect(KeychainCriterion.InternetProtocol.other("imap") == .other("imap"))
            #expect(KeychainCriterion.InternetProtocol.https != .http)
        }
    }

    #if os(iOS)
        extension ValueConformanceTests {
            @Test func credentialsAreSendableAndEquatable() {
                requireSendable(BiometricService.Credentials.self)
                let credentials = BiometricService.Credentials(username: "user", password: "secret")
                #expect(credentials == BiometricService.Credentials(username: "user", password: "secret"))
            }
        }
    #endif
#endif
