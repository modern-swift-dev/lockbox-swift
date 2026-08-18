#if canImport(Security)
import Foundation

/// Errors produced while encoding data or working with Keychain Services.
public enum KeychainError: Swift.Error {

    /// The value could not be encoded into the data required by a Keychain operation.
    case encodingFailed

    /// A Security-framework operation failed.
    ///
    /// - Parameters:
    ///   - status: The OS status code returned by the framework.
    ///   - message: A system-provided explanation, when available.
    case underlyingError(status: OSStatus, message: String?)

    /// A human-readable description containing the status code and available message.
    public var localizedDescription: String {
        switch self {
            case .encodingFailed:
                return "encoding failed"
            case let .underlyingError(status, message):
                if let message {
                    return "\(status) - \(message)"
                }
                return "\(status) - unknown error"
        }
    }
}

public extension OSStatus {

    /// Whether this status represents a successful Security-framework operation.
    var isSuccessful: Bool {
        self == noErr
    }

    /// Whether this status represents no matching Keychain item.
    var isNotFound: Bool {
        self == errSecItemNotFound
    }

    /// The Security framework's message for this status, when one is available.
    var errorMessage: String? {
        if let msg = SecCopyErrorMessageString(self, nil) {
            return msg as String
        }
        return nil
    }

}

#endif
