import Foundation
import Lockbox
import Security
import Testing

/// Exercises the iOS data protection keychain through Lockbox's public API.
///
/// These tests run inside the example app, which gives them the keychain entitlement
/// that SwiftPM test bundles lack on the simulator.
@Suite(.serialized) struct KeychainIntegrationTests {

    private let service = "com.example.LockboxExampleTests.\(UUID().uuidString)"

    private func cleanUp(_ passwords: KeychainPassword...) {
        for password in passwords {
            try? password.remove()
        }
    }

    @Test func genericPasswordRoundTrip() throws {
        let password = KeychainPassword.generic(service: service, account: "user")
        defer { cleanUp(password) }

        try password.set(string: "first")
        #expect(try password.getString() == "first")

        try password.set(string: "second")
        #expect(try password.getString() == "second")

        try password.remove()
        #expect(try password.getString() == nil)
        try password.remove()
    }

    /// The `kSecAttrAccessible` value Keychain Services stored for a handle's item.
    private func storedAccessibility(of password: KeychainPassword) throws -> String? {
        let query = password.criteria + [.limitOne, .returnAttributes(true)]
        var result: AnyObject?
        let status = SecItemCopyMatching(query.query, &result)
        try #require(status == errSecSuccess)
        return (result as? [String: Any])?[kSecAttrAccessible as String] as? String
    }

    @Test func accessibilityAndMetadataChangeOnUpdate() throws {
        let first = KeychainPassword.generic(
            service: service,
            account: "attributes",
            protection: .accessibility(.whenUnlocked),
            label: "First"
        )
        let second = KeychainPassword.generic(
            service: service,
            account: "attributes",
            protection: .accessibility(.afterFirstUnlockThisDeviceOnly),
            label: "Second",
            comment: "Comment"
        )
        defer { cleanUp(first, second) }

        try first.set(string: "first")
        #expect(try storedAccessibility(of: first) == kSecAttrAccessibleWhenUnlocked as String)
        try second.set(string: "second")

        let record = try #require(try second.criteria.retrieve())
        #expect(record.label == "Second")
        #expect(record.comment == "Comment")
        #expect(try first.getString() == "second")
        #expect(try storedAccessibility(of: second) == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
    }

    @Test func accessControlledItemCanBeUpdated() throws {
        let accessControl = try #require(SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            nil
        ))
        let password = KeychainPassword.generic(
            service: service,
            account: "access-control",
            protection: .accessControl(accessControl)
        )
        defer { cleanUp(password) }

        try password.set(string: "first")
        try password.set(string: "second")

        #expect(try password.getString() == "second")
        #expect(try storedAccessibility(of: password) == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }

    @Test func protectionChangesOnUpdate() throws {
        let afterFirstUnlock = try #require(SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [],
            nil
        ))
        let whenUnlocked = try #require(SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            nil
        ))
        let accessible = KeychainPassword.generic(
            service: service,
            account: "protection-change",
            protection: .accessibility(.whenUnlocked)
        )
        let firstAccessControl = KeychainPassword.generic(
            service: service,
            account: "protection-change",
            protection: .accessControl(afterFirstUnlock)
        )
        let secondAccessControl = KeychainPassword.generic(
            service: service,
            account: "protection-change",
            protection: .accessControl(whenUnlocked)
        )
        defer { cleanUp(accessible) }

        try accessible.set(string: "first")
        #expect(try storedAccessibility(of: accessible) == kSecAttrAccessibleWhenUnlocked as String)

        try firstAccessControl.set(string: "second")
        #expect(try storedAccessibility(of: accessible) == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)

        try secondAccessControl.set(string: "third")
        #expect(try storedAccessibility(of: accessible) == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        #expect(try accessible.getString() == "third")
    }

    /// Documents why `KeychainPassword.Protection` allows only one kind of protection.
    @Test func keychainRejectsAccessibilityWithAccessControl() throws {
        let accessControl = try #require(SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            nil
        ))
        let password = KeychainPassword.generic(service: service, account: "both-protections")
        defer { cleanUp(password) }
        let bothProtections: [KeychainCriterion] = [
            .accessible(.whenUnlockedThisDeviceOnly),
            .accessControl(accessControl)
        ]

        #expect(throws: KeychainError.underlyingError(status: errSecParam, message: errSecParam.errorMessage)) {
            try (password.criteria + bothProtections).create(data: Data("secret".utf8))
        }

        try password.set(string: "existing")
        let update = ([.data(Data("new".utf8))] + bothProtections).query
        #expect(SecItemUpdate(password.criteria.query, update) == errSecParam)
    }

    @Test func dataProtectionKeychainOptionWorksOnIOS() throws {
        let password = KeychainPassword.generic(service: service, account: "data-protection", useDataProtectionKeychain: true)
        let plain = KeychainPassword.generic(service: service, account: "data-protection")
        defer { cleanUp(password) }

        try password.set(string: "secret")

        // iOS always uses the data protection keychain, so both handles find the item.
        #expect(try password.getString() == "secret")
        #expect(try plain.getString() == "secret")
    }

    @Test func internetPasswordRoundTrip() throws {
        let url = try #require(URL(string: "https://api.example.com/login"))
        let password = KeychainPassword.internet(url: url, securityDomain: service, account: "user")
        defer { cleanUp(password) }

        try password.set(string: "secret")
        #expect(try password.getString() == "secret")

        let listed = try KeychainPassword.allInternetPassword(securityDomain: service)
        #expect(try listed.compactMap { try $0.getString() } == ["secret"])
    }

    @Test func findAllReturnsDeviceOnlyAndSynchronizableItems() throws {
        let local = KeychainPassword.generic(service: service, account: "local", synchronizable: false)
        let synced = KeychainPassword.generic(service: service, account: "synced", synchronizable: true)
        defer { cleanUp(local, synced) }

        try local.set(string: "local")
        try synced.set(string: "synced")

        let handles = try KeychainPassword.allGenericPassword(service: service)
        let values = try handles.compactMap { try $0.getString() }.sorted()
        #expect(values == ["local", "synced"])
    }

    @Test func duplicateCreateThrowsTypedError() throws {
        let password = KeychainPassword.generic(service: service, account: "duplicate")
        defer { cleanUp(password) }

        try password.criteria.create(data: Data("first".utf8))

        #expect(throws: KeychainError.duplicateItem) {
            try password.criteria.create(data: Data("second".utf8))
        }
    }
}
