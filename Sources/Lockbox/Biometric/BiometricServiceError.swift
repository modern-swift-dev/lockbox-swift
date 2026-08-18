#if canImport(Security)
#if !os(watchOS) && !os(tvOS) && !os(visionOS)
import Foundation
import LocalAuthentication

/// Errors produced while authenticating or accessing biometric credentials.
public enum BiometricServiceError: Swift.Error {

    /// The device doesn't support biometric authentication.
    case unsupported

    /// Biometric authentication isn't configured on the device, or credentials are absent.
    case unconfigured

    /// Authentication or credential access failed.
    case failed

    /// Biometric authentication is locked after too many failed attempts.
    case lockedOut

    /// The user or system cancelled authentication.
    case cancelled

    /// Biometric authentication is temporarily unavailable.
    case unavailable

    /// Local Authentication returned an unrecognized error.
    case unknown

    /// An error that couldn't be represented by another case.
    ///
    /// - Parameter error: The original error.
    case underlying(any Swift.Error)

    static func from(error: any Error) -> BiometricServiceError {
        if let laError = error as? LAError {
            return from(error: laError)
        }

        return .underlying(error)
    }

    /// A Boolean value that indicates whether biometric authentication is locked out.
    public var isLockedOut: Bool {
        switch self {
            case .lockedOut:
                true
            default:
                false
        }
    }

    /// Map a LAError to a BiometricService.Error type
    static func from(error: LAError) -> BiometricServiceError {

        switch error.code {
            case .biometryLockout,
                 .touchIDLockout:
                return .lockedOut
            case .biometryNotAvailable,
                 .touchIDNotAvailable:
                return .unsupported
            case .biometryNotEnrolled,
                 .touchIDNotEnrolled,
                 .biometryNotPaired,
                 .passcodeNotSet:
                return .unconfigured
            case .appCancel,
                 .userCancel,
                 .systemCancel:
                return .cancelled
            case .userFallback,
                 .invalidContext,
                 .authenticationFailed,
                 .invalidDimensions:
                return .failed
            #if !os(iOS)
            case .watchNotAvailable:
                return .unavailable
            #endif
        case .notInteractive,
                 .biometryDisconnected:
                return .unavailable
        case .companionNotAvailable:
                return .unavailable
            @unknown default:
                return .unknown
        }
    }
}
#endif

#endif
