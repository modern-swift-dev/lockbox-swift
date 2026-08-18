#if os(macOS) || os(iOS)
import Foundation
@testable import Lockbox
import Testing

@Suite(.serialized) struct SecurityClassTests {

    @Test func genericPasswordQueryValue() {
        let value = KeychainCriterion.SecurityClass.genericPassword.queryValue
        #expect(value == (kSecClassGenericPassword as String))
    }

    @Test func internetPasswordQueryValue() {
        let value = KeychainCriterion.SecurityClass.internetPassword.queryValue
        #expect(value == (kSecClassInternetPassword as String))
    }

    @Test func certificateQueryValue() {
        let value = KeychainCriterion.SecurityClass.certificate.queryValue
        #expect(value == (kSecClassCertificate as String))
    }

    @Test func keyQueryValue() {
        let value = KeychainCriterion.SecurityClass.key.queryValue
        #expect(value == (kSecClassKey as String))
    }

    @Test func identityQueryValue() {
        let value = KeychainCriterion.SecurityClass.identity.queryValue
        #expect(value == (kSecClassIdentity as String))
    }
}
#endif
