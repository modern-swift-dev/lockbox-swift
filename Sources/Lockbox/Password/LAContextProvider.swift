#if canImport(Security)
#if !os(watchOS) && !os(tvOS)
import Foundation
import LocalAuthentication

/// A sendable factory that supplies an `LAContext` for a keychain operation.
///
/// Pass a provider to ``KeychainPassword/generic(service:account:accessGroup:synchronizable:accessControl:contextProvider:)``
/// or ``KeychainPassword/internet(url:authenticationType:service:account:accessGroup:synchronizable:accessControl:contextProvider:)``
/// when the item's access control requires Local Authentication. The provider is
/// evaluated while constructing a Security framework query.
public typealias LAContextProvider = @Sendable () -> LAContext
#endif

#endif
