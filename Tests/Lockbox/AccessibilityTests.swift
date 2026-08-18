#if os(macOS) || os(iOS)
import Foundation
@testable import Lockbox
import Testing

@Suite(.serialized) struct AccessibilityTests {

    @Test func whenUnlockedQueryValue() throws {
        let value = try #require(KeychainCriterion.Accessibility.whenUnlocked.queryValue as? String)
        #expect(value == kSecAttrAccessibleWhenUnlocked as String)
    }

    @Test func whenUnlockedThisDeviceOnlyQueryValue() throws {
        let value = try #require(KeychainCriterion.Accessibility.whenUnlockedThisDeviceOnly.queryValue as? String)
        #expect(value == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }

    @Test func whenPasswordSetThisDeviceOnlyQueryValue() throws {
        let value = try #require(KeychainCriterion.Accessibility.whenPasswordSetThisDeviceOnly.queryValue as? String)
        #expect(value == kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String)
    }

    @Test func afterFirstUnlockQueryValue() throws {
        let value = try #require(KeychainCriterion.Accessibility.afterFirstUnlock.queryValue as? String)
        #expect(value == kSecAttrAccessibleAfterFirstUnlock as String)
    }

    @Test func afterFirstUnlockThisDeviceOnlyQueryValue() throws {
        let value = try #require(KeychainCriterion.Accessibility.afterFirstUnlockThisDeviceOnly.queryValue as? String)
        #expect(value == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
    }

    @Test func criterionProperty() throws {
        let accessibility = KeychainCriterion.Accessibility.whenUnlocked
        let criterion = accessibility.criterion
        if case let .accessible(accessValue) = criterion {
            let value = try #require(accessValue.queryValue as? String)
            #expect(value == kSecAttrAccessibleWhenUnlocked as String)
        } else {
            Issue.record("Expected .accessible criterion")
        }
    }
}
#endif
