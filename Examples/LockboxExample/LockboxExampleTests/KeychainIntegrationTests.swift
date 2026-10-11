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

    @Test func accessibilityAndMetadataChangeOnUpdate() throws {
        let first = KeychainPassword.generic(
            service: service,
            account: "attributes",
            accessibility: .whenUnlocked,
            label: "First"
        )
        let second = KeychainPassword.generic(
            service: service,
            account: "attributes",
            accessibility: .afterFirstUnlockThisDeviceOnly,
            label: "Second",
            comment: "Comment"
        )
        defer { cleanUp(first, second) }

        try first.set(string: "first")
        try second.set(string: "second")

        let record = try #require(try second.criteria.retrieve())
        #expect(record.label == "Second")
        #expect(record.comment == "Comment")
        #expect(try first.getString() == "second")
    }

    @Test func accessControlledItemCanBeUpdated() throws {
        let accessControl = try #require(SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            nil
        ))
        let password = KeychainPassword.generic(service: service, account: "access-control", accessControl: accessControl)
        defer { cleanUp(password) }

        try password.set(string: "first")
        try password.set(string: "second")

        #expect(try password.getString() == "second")
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
