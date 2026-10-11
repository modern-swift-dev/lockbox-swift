#if canImport(Security) && canImport(LocalAuthentication) && !os(watchOS) && !os(tvOS) && !os(visionOS)
    import CryptoKit
    import Foundation

    /// The biometric state recorded after credentials for one keychain item were saved.
    struct BiometricBaseline {
        let fileURL: URL

        /// Locates the baseline for a keychain item.
        ///
        /// Each service, account, and access group has its own file, so items don't
        /// overwrite each other's baselines.
        static func forItem(
            service: String,
            account: String,
            accessGroup: String?,
            in directory: URL = .applicationSupportDirectory
        ) -> BiometricBaseline {
            let identity = [service, account, accessGroup ?? ""].joined(separator: "\n")
            let digest = SHA256.hash(data: Data(identity.utf8)).map { String(format: "%02x", $0) }.joined()
            return BiometricBaseline(
                fileURL: directory
                    .appendingPathComponent("Lockbox", isDirectory: true)
                    .appendingPathComponent("Biometrics", isDirectory: true)
                    .appendingPathComponent("\(digest).biometrics")
            )
        }

        func hasChanged(from data: Data) throws -> Bool {
            guard FileManager.default.fileExists(atPath: fileURL.path) else {
                return false
            }
            return try Data(contentsOf: fileURL) != data
        }

        /// Saves the state, excluding it from backups because it describes this device only.
        func record(_ data: Data) throws {
            try FileManager.default.createDirectory(
                at: fileURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try data.write(to: fileURL, options: .atomic)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var url = fileURL
            try url.setResourceValues(values)
        }

        func remove() throws {
            guard FileManager.default.fileExists(atPath: fileURL.path) else {
                return
            }
            try FileManager.default.removeItem(at: fileURL)
        }
    }
#endif
