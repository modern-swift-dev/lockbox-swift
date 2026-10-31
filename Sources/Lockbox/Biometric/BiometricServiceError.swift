#if canImport(Security)
    #if !os(watchOS) && !os(tvOS) && !os(visionOS)
        import Foundation
        import LocalAuthentication

        /// Errors produced while authenticating or accessing biometric credentials.
        public enum BiometricServiceError: LocalizedError {

            /// The device doesn't support biometric authentication.
            case unsupported

            /// Biometric authentication isn't configured on the device.
            case unconfigured

            /// No credentials are stored.
            case noCredentials

            /// Authentication or credential access failed.
            case failed

            /// The user chose the fallback button instead of authenticating.
            ///
            /// Offer the app's own sign-in, such as a password form.
            case userFallback

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

            /// A description of the error suitable for display.
            public var errorDescription: String? {
                switch self {
                    case .unsupported:
                        "This device doesn't support biometric authentication."
                    case .unconfigured:
                        "Biometric authentication isn't set up on this device."
                    case .noCredentials:
                        "No saved credentials were found."
                    case .failed:
                        "Biometric authentication failed."
                    case .userFallback:
                        "The user chose another way to sign in."
                    case .lockedOut:
                        "Biometric authentication is locked after too many failed attempts."
                    case .cancelled:
                        "Biometric authentication was cancelled."
                    case .unavailable:
                        "Biometric authentication is temporarily unavailable."
                    case .unknown:
                        "Biometric authentication failed with an unknown error."
                    case let .underlying(error):
                        error.localizedDescription
                }
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
                    case .userFallback:
                        return .userFallback
                    case .invalidContext,
                         .authenticationFailed,
                         .invalidDimensions:
                        return .failed
                    case .notInteractive,
                         .biometryDisconnected:
                        return .unavailable
                    case .companionNotAvailable:
                        return .unavailable
                    #if !os(iOS)
                        case .watchNotAvailable:
                            return .unavailable
                    #endif
                    @unknown default:
                        return .unknown
                }
            }
        }
    #endif

#endif
