#if os(macOS) || os(iOS)
import Foundation
@testable import Lockbox
import Testing

@Suite(.serialized) struct BiometricServiceResultTests {

    @Test func successCase() {
        let result = BiometricServiceResult.success(username: "user@test.com", password: "secret123")
        if case let .success(username, password) = result {
            #expect(username == "user@test.com")
            #expect(password == "secret123")
        } else {
            Issue.record("Expected .success")
        }
    }

    @Test func biometricChangedCase() {
        let result = BiometricServiceResult.biometricChanged(username: "user@test.com", password: "secret123")
        if case let .biometricChanged(username, password) = result {
            #expect(username == "user@test.com")
            #expect(password == "secret123")
        } else {
            Issue.record("Expected .biometricChanged")
        }
    }
}
#endif
