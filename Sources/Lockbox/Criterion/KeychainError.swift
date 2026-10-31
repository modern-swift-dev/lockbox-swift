#if canImport(Security)
    import Foundation

    /// Errors produced while working with Keychain Services.
    ///
    /// Statuses that callers commonly handle have their own cases. Every other status
    /// is reported as ``underlyingError(status:message:)``. Two errors are equal when they
    /// have the same ``status``.
    public enum KeychainError: LocalizedError, Equatable {

        /// No item matches the query (`errSecItemNotFound`).
        case itemNotFound

        /// An item with the same primary key already exists (`errSecDuplicateItem`).
        case duplicateItem

        /// The item can't be accessed without user interaction, for example because the
        /// device is locked (`errSecInteractionNotAllowed`).
        case interactionNotAllowed

        /// The app lacks the keychain entitlement the query requires
        /// (`errSecMissingEntitlement`).
        case missingEntitlement

        /// Authentication for the item failed (`errSecAuthFailed`).
        case authenticationFailed

        /// The user cancelled the authentication prompt (`errSecUserCanceled`).
        case userCanceled

        /// A Security-framework operation failed with another status.
        ///
        /// - Parameters:
        ///   - status: The OS status code returned by the framework.
        ///   - message: A system-provided explanation, when available.
        case underlyingError(status: OSStatus, message: String?)

        /// Creates the error that represents a Security-framework status.
        ///
        /// - Parameter status: A failing status returned by Keychain Services.
        public init(status: OSStatus) {
            switch status {
                case errSecItemNotFound: self = .itemNotFound
                case errSecDuplicateItem: self = .duplicateItem
                case errSecInteractionNotAllowed: self = .interactionNotAllowed
                case errSecMissingEntitlement: self = .missingEntitlement
                case errSecAuthFailed: self = .authenticationFailed
                case errSecUserCanceled: self = .userCanceled
                default: self = .underlyingError(status: status, message: status.errorMessage)
            }
        }

        /// The Security-framework status this error represents.
        public var status: OSStatus {
            switch self {
                case .itemNotFound: errSecItemNotFound
                case .duplicateItem: errSecDuplicateItem
                case .interactionNotAllowed: errSecInteractionNotAllowed
                case .missingEntitlement: errSecMissingEntitlement
                case .authenticationFailed: errSecAuthFailed
                case .userCanceled: errSecUserCanceled
                case let .underlyingError(status, _): status
            }
        }

        /// Returns whether two errors represent the same Security-framework status.
        ///
        /// The system message is ignored, so `.underlyingError(status: x, message: nil)`
        /// equals `KeychainError(status: x)`.
        public static func == (lhs: KeychainError, rhs: KeychainError) -> Bool {
            lhs.status == rhs.status
        }

        /// A human-readable description containing the status code and available message.
        public var localizedDescription: String {
            let message = switch self {
                case let .underlyingError(_, message): message
                default: status.errorMessage
            }
            return "\(status) - \(message ?? "unknown error")"
        }

        /// Preserves the description when this value is handled as `any Error` or `NSError`.
        public var errorDescription: String? {
            localizedDescription
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
