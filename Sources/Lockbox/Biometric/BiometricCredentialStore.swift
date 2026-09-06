#if canImport(Security) && os(iOS)
    import Foundation

    /// The storage operations used by biometric credential flows.
    protocol BiometricCredentialStore: Sendable {
        func getData() throws -> Data?
        func set(data: Data) throws
        func remove() throws
    }

    extension KeychainPassword: BiometricCredentialStore {}
#endif
