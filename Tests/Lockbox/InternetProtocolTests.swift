#if os(macOS) || os(iOS)
import Foundation
@testable import Lockbox
import Testing

@Suite(.serialized) struct InternetProtocolTests {

    @Test func httpQueryValue() {
        let value = KeychainCriterion.InternetProtocol.http.queryValue
        #expect(value == (kSecAttrProtocolHTTP as String))
    }

    @Test func httpsQueryValue() {
        let value = KeychainCriterion.InternetProtocol.https.queryValue
        #expect(value == (kSecAttrProtocolHTTPS as String))
    }

    @Test func ftpQueryValue() {
        let value = KeychainCriterion.InternetProtocol.ftp.queryValue
        #expect(value == (kSecAttrProtocolFTP as String))
    }

    @Test func ftpsQueryValue() {
        let value = KeychainCriterion.InternetProtocol.ftps.queryValue
        #expect(value == (kSecAttrProtocolFTPS as String))
    }

    @Test func smbQueryValue() {
        let value = KeychainCriterion.InternetProtocol.smb.queryValue
        #expect(value == (kSecAttrProtocolSMB as String))
    }

    @Test func sshQueryValue() {
        let value = KeychainCriterion.InternetProtocol.ssh.queryValue
        #expect(value == (kSecAttrProtocolSSH as String))
    }
}
#endif
