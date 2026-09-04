#if canImport(Security)
import os.log
import Security

#if canImport(LocalAuthentication) && !os(tvOS)
import LocalAuthentication

extension LAContext: @unchecked @retroactive Sendable {}
#endif

extension SecAccessControl: @unchecked @retroactive Sendable {}

#if canImport(LocalAuthentication) && !os(watchOS) && !os(tvOS) && !os(visionOS)
import Foundation

public extension LAContext {

    /// Compares the current biometric state without changing the saved baseline.
    internal func hasBiometricDataChanged(_: LAAccessControlOperation) -> Bool {
        guard let newData = domainState.stateHash, let baseline = biometricBaseline else {
            return false
        }
        do {
            return try baseline.hasChanged(from: newData)
        } catch {
            os_log("%{public}@", type: .error, error.localizedDescription)
            return true
        }
    }

    /// Records a baseline only after the caller has successfully stored its credentials.
    internal func recordBiometricState() throws {
        guard let data = domainState.stateHash, let baseline = biometricBaseline else {
            return
        }
        try baseline.record(data)
    }

    private var biometricBaseline: BiometricBaseline? {
        guard let bundleId = Bundle.main.bundleIdentifier else {
            return nil
        }
        return BiometricBaseline(
            fileURL: URL.applicationSupportDirectory.appendingPathComponent("\(bundleId).biometrics")
        )
    }

    /// Evaluates access using the strategy selected by a security mode.
    ///
    /// - Parameters:
    ///   - accessControl: The access-control object protecting the keychain item.
    ///   - operation: The keychain operation to authorize.
    ///   - mode: The strategy used to evaluate authentication.
    ///   - localizedReason: The localized explanation shown to the user.
    /// - Returns: The outcome of the authentication evaluation.
    func evaluate(
        accessControl: SecAccessControl,
        operation: LAAccessControlOperation,
        securityMode mode: LAContext.SecurityMode,
        localizedReason: String
    ) async -> PolicyEvaluationResult {
        switch mode {
            case .highest:
                await evaluate(accessControl: accessControl, operation: operation, localizedReason: localizedReason)
            case .normal:
                await evaluate(policy: .deviceOwnerAuthentication, operation: operation, reason: localizedReason)
        }
    }

    /// Evaluates an access-control object for a keychain operation.
    ///
    /// - Parameters:
    ///   - accessControl: The access-control object protecting the keychain item.
    ///   - operation: The keychain operation to authorize, such as `.useItem` or `.createItem`.
    ///   - localizedReason: The localized explanation shown to the user.
    /// - Returns: The outcome of the authentication evaluation.
    func evaluate(
        accessControl: SecAccessControl,
        operation: LAAccessControlOperation,
        localizedReason: String
    ) async -> PolicyEvaluationResult {
        await withCheckedContinuation { [weak self] continuation in
            guard let self else {
                return continuation.resume(returning: .failed)
            }
            self.evaluateAccessControl(accessControl, operation: operation, localizedReason: localizedReason, reply: { [weak self] result, error in
                guard let self else {
                    return continuation.resume(returning: .failed)
                }

                continuation.resume(returning: PolicyEvaluationResult.from(context: self, operation: operation, result: result, error: error))
            })
        }
    }

    /// Evaluates a Local Authentication policy for a keychain operation.
    ///
    /// - Parameters:
    ///   - policy: The authentication policy to evaluate.
    ///   - operation: The keychain operation associated with the evaluation.
    ///   - reason: The localized explanation shown to the user.
    /// - Returns: The outcome of the authentication evaluation.
    func evaluate(
        policy: LAPolicy,
        operation: LAAccessControlOperation,
        reason: String
    ) async -> PolicyEvaluationResult {
        await withCheckedContinuation { [weak self] continuation in
            guard let self else {
                return continuation.resume(returning: .failed)
            }
            self.evaluatePolicy(policy, localizedReason: reason) { [weak self] result, error in
                guard let self else {
                    return continuation.resume(returning: .failed)
                }
                continuation.resume(returning: PolicyEvaluationResult.from(context: self, operation: operation, result: result, error: error))
            }
        }
    }
}
#endif

#endif
