#if os(macOS) || os(iOS)
import Foundation
@testable import Lockbox
import Testing

@Suite(.serialized) struct AuthenticationTypeTests {

    @Test func ntlmQueryValue() {
        let value = KeychainCriterion.AuthenticationType.ntlm.queryValue
        #expect(value == (kSecAttrAuthenticationTypeNTLM as String))
    }

    @Test func msnQueryValue() {
        let value = KeychainCriterion.AuthenticationType.msn.queryValue
        #expect(value == (kSecAttrAuthenticationTypeMSN as String))
    }

    @Test func dpaQueryValue() {
        let value = KeychainCriterion.AuthenticationType.dpa.queryValue
        #expect(value == (kSecAttrAuthenticationTypeDPA as String))
    }

    @Test func rpaQueryValue() {
        let value = KeychainCriterion.AuthenticationType.rpa.queryValue
        #expect(value == (kSecAttrAuthenticationTypeRPA as String))
    }

    @Test func httpBasicQueryValue() {
        let value = KeychainCriterion.AuthenticationType.httpBasic.queryValue
        #expect(value == (kSecAttrAuthenticationTypeHTTPBasic as String))
    }

    @Test func httpDigestQueryValue() {
        let value = KeychainCriterion.AuthenticationType.httpDigest.queryValue
        #expect(value == (kSecAttrAuthenticationTypeHTTPDigest as String))
    }

    @Test func htmlFormQueryValue() {
        let value = KeychainCriterion.AuthenticationType.htmlForm.queryValue
        #expect(value == (kSecAttrAuthenticationTypeHTMLForm as String))
    }

    @Test func defaultQueryValue() {
        let value = KeychainCriterion.AuthenticationType.default.queryValue
        #expect(value == (kSecAttrAuthenticationTypeDefault as String))
    }

    @Test func fromNTLM() {
        let result = KeychainCriterion.AuthenticationType.from(kSecAttrAuthenticationTypeNTLM as String)
        #expect(result.queryValue == KeychainCriterion.AuthenticationType.ntlm.queryValue)
    }

    @Test func fromMSN() {
        let result = KeychainCriterion.AuthenticationType.from(kSecAttrAuthenticationTypeMSN as String)
        #expect(result.queryValue == KeychainCriterion.AuthenticationType.msn.queryValue)
    }

    @Test func fromDPA() {
        let result = KeychainCriterion.AuthenticationType.from(kSecAttrAuthenticationTypeDPA as String)
        #expect(result.queryValue == KeychainCriterion.AuthenticationType.dpa.queryValue)
    }

    @Test func fromRPA() {
        let result = KeychainCriterion.AuthenticationType.from(kSecAttrAuthenticationTypeRPA as String)
        #expect(result.queryValue == KeychainCriterion.AuthenticationType.rpa.queryValue)
    }

    @Test func fromHTTPBasic() {
        let result = KeychainCriterion.AuthenticationType.from(kSecAttrAuthenticationTypeHTTPBasic as String)
        #expect(result.queryValue == KeychainCriterion.AuthenticationType.httpBasic.queryValue)
    }

    @Test func fromHTTPDigest() {
        let result = KeychainCriterion.AuthenticationType.from(kSecAttrAuthenticationTypeHTTPDigest as String)
        #expect(result.queryValue == KeychainCriterion.AuthenticationType.httpDigest.queryValue)
    }

    @Test func fromHTMLForm() {
        let result = KeychainCriterion.AuthenticationType.from(kSecAttrAuthenticationTypeHTMLForm as String)
        #expect(result.queryValue == KeychainCriterion.AuthenticationType.htmlForm.queryValue)
    }

    @Test func fromDefault() {
        let result = KeychainCriterion.AuthenticationType.from(kSecAttrAuthenticationTypeDefault as String)
        #expect(result.queryValue == KeychainCriterion.AuthenticationType.default.queryValue)
    }

    @Test func fromUnknownReturnsDefault() {
        let result = KeychainCriterion.AuthenticationType.from("unknown_type")
        #expect(result.queryValue == KeychainCriterion.AuthenticationType.default.queryValue)
    }
}
#endif
