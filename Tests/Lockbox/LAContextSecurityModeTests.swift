#if canImport(Security)
#if os(macOS) || os(iOS)
import Foundation
import LocalAuthentication
@testable import Lockbox
import Testing

@Suite(.serialized) struct LAContextSecurityModeTests {

    @Test func adaptReturnsNormalOnSimulator() {
        // On simulator, adapt should return .normal
        let mode = LAContext.SecurityMode.adapt(.highest)
        #if targetEnvironment(simulator)
        if case .normal = mode {} else { Issue.record("Expected .normal on simulator") }
        #else
        if case .highest = mode {} else { Issue.record("Expected .highest on device") }
        #endif
    }

    @Test func adaptDefaultsToHighest() {
        let mode = LAContext.SecurityMode.adapt()
        #if targetEnvironment(simulator)
        if case .normal = mode {} else { Issue.record("Expected .normal on simulator") }
        #else
        if case .highest = mode {} else { Issue.record("Expected .highest on device") }
        #endif
    }
}
#endif

#endif
