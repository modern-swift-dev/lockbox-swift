#if canImport(Security) && canImport(LocalAuthentication) && !os(watchOS) && !os(tvOS) && !os(visionOS)
    import Foundation

    /// The last biometric state recorded after a successful credential save.
    struct BiometricBaseline {
        let fileURL: URL

        func hasChanged(from data: Data) throws -> Bool {
            guard FileManager.default.fileExists(atPath: fileURL.path) else {
                return false
            }
            return try Data(contentsOf: fileURL) != data
        }

        func record(_ data: Data) throws {
            try FileManager.default.createDirectory(
                at: fileURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try data.write(to: fileURL, options: .atomic)
        }
    }
#endif
