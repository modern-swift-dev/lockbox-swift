#if canImport(Security)
import LocalAuthentication
import os.log

#if !os(tvOS)
extension LAContext: @unchecked @retroactive Sendable {}
#endif

extension SecAccessControl: @unchecked @retroactive Sendable {}

#if !os(watchOS) && !os(tvOS) && !os(visionOS)
import Foundation

public extension LAContext {

    /// Evaluate if the biometric data has changed since `write` operation to the keychain
    internal func hasBiometricDataChanged(_ operation: LAAccessControlOperation) -> Bool {
        guard let newData = domainState.stateHash else {
            return false
        }

        guard let bundleId = Bundle.main.bundleIdentifier else {
            return false
        }

        do {
            let fileUrl = URL.applicationSupportDirectory.appendingPathComponent("\(bundleId).biometrics")
            if FileManager.default.fileExists(atPath: fileUrl.path) {
                let previousData = try Data(contentsOf: fileUrl)
                if previousData != newData {
                    return true
                }
            }

            // We write the opaque data structure ONLY if we're creating an item. otherwise
            // all other operation (which should be `.useItem`) will simply not write it
            // down.
            if operation == .createItem {
                try newData.write(to: fileUrl, options: [.atomicWrite])
            }

            return false
        } catch {
            os_log("%{public}@", type: .error, error.localizedDescription)
            return true
        }
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
