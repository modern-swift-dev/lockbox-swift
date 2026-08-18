import LocalAuthentication
import Lockbox
import SwiftUI

@main
struct LockboxExampleApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @StateObject private var model = ExampleViewModel()

    var body: some View {
        NavigationStack {
            Form {
                Section("Generic Password") {
                    TextField("Account", text: $model.genericAccount)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Password", text: $model.genericPassword)
                        .textContentType(.password)

                    Button("Save Generic Password") {
                        model.saveGenericPassword()
                    }
                    Button("Read Generic Password") {
                        model.readGenericPassword()
                    }
                    Button("Delete Generic Password", role: .destructive) {
                        model.deleteGenericPassword()
                    }
                }

                Section("Internet Password") {
                    TextField("URL", text: $model.internetURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                    TextField("Account", text: $model.internetAccount)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Password", text: $model.internetPassword)
                        .textContentType(.password)

                    Button("Save Internet Password") {
                        model.saveInternetPassword()
                    }
                    Button("Read Internet Password") {
                        model.readInternetPassword()
                    }
                    Button("Delete Internet Password", role: .destructive) {
                        model.deleteInternetPassword()
                    }
                }

                Section("Biometric Credentials") {
                    TextField("Email", text: $model.biometricEmail)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textContentType(.username)
                        .keyboardType(.emailAddress)
                    SecureField("Password", text: $model.biometricPassword)
                        .textContentType(.password)

                    Text(model.biometricAvailability)
                        .foregroundStyle(.secondary)

                    Button("Save with Biometrics") {
                        Task {
                            await model.saveBiometricCredentials()
                        }
                    }
                    Button("Retrieve with Biometrics") {
                        Task {
                            await model.retrieveBiometricCredentials()
                        }
                    }
                    Button("Forget Biometric Credentials", role: .destructive) {
                        model.forgetBiometricCredentials()
                    }
                }

                Section("Status") {
                    Text(model.status)
                        .foregroundStyle(model.isError ? .red : .secondary)
                }
            }
            .navigationTitle("Lockbox Example")
        }
    }
}

@MainActor
private final class ExampleViewModel: ObservableObject {
    @Published var genericAccount = "example-account"
    @Published var genericPassword = ""
    @Published var internetURL = "https://example.com/login"
    @Published var internetAccount = "example-account"
    @Published var internetPassword = ""
    @Published var biometricEmail = "user@example.com"
    @Published var biometricPassword = ""
    @Published private(set) var status = "Choose an operation to begin."
    @Published private(set) var isError = false

    private let service = Bundle.main.bundleIdentifier ?? "com.example.LockboxExample"

    private var genericKeychainPassword: KeychainPassword {
        KeychainPassword.generic(service: service, account: genericAccount)
    }

    private func internetKeychainPassword() -> KeychainPassword? {
        guard let url = URL(string: internetURL), url.host != nil else {
            reportError("Enter a complete internet URL, such as https://example.com/login.")
            return nil
        }

        return KeychainPassword.internet(
            url: url,
            service: service,
            account: internetAccount
        )
    }

    var biometricAvailability: String {
        let biometricService = makeBiometricService()
        if !biometricService.supportedByDevice {
            return "This device does not support Face ID or Touch ID."
        }
        if !biometricService.isProperlyConfigured {
            return "Configure Face ID or Touch ID before using this example."
        }
        return "Biometric authentication is available."
    }

    func saveGenericPassword() {
        do {
            try genericKeychainPassword.set(string: genericPassword)
            reportSuccess("Generic password saved.")
        } catch {
            report(error, action: "saving the generic password")
        }
    }

    func readGenericPassword() {
        do {
            guard let password = try genericKeychainPassword.getString() else {
                reportError("No generic password was found for this account.")
                return
            }
            genericPassword = password
            reportSuccess("Generic password retrieved into the secure field.")
        } catch {
            report(error, action: "reading the generic password")
        }
    }

    func deleteGenericPassword() {
        do {
            try genericKeychainPassword.remove()
            genericPassword = ""
            reportSuccess("Generic password deleted.")
        } catch {
            report(error, action: "deleting the generic password")
        }
    }

    func saveInternetPassword() {
        guard let password = internetKeychainPassword() else {
            return
        }

        do {
            try password.set(string: internetPassword)
            reportSuccess("Internet password saved.")
        } catch {
            report(error, action: "saving the internet password")
        }
    }

    func readInternetPassword() {
        guard let keychainPassword = internetKeychainPassword() else {
            return
        }

        do {
            guard let password = try keychainPassword.getString() else {
                reportError("No internet password was found for this URL and account.")
                return
            }
            internetPassword = password
            reportSuccess("Internet password retrieved into the secure field.")
        } catch {
            report(error, action: "reading the internet password")
        }
    }

    func deleteInternetPassword() {
        guard let password = internetKeychainPassword() else {
            return
        }

        do {
            try password.remove()
            internetPassword = ""
            reportSuccess("Internet password deleted.")
        } catch {
            report(error, action: "deleting the internet password")
        }
    }

    func saveBiometricCredentials() async {
        do {
            try await makeBiometricService().save(email: biometricEmail, password: biometricPassword)
            reportSuccess("Biometric credentials saved.")
        } catch {
            report(error, action: "saving biometric credentials")
        }
    }

    func retrieveBiometricCredentials() async {
        do {
            let result = try await makeBiometricService().retrieve()
            switch result {
                case let .success(username, password), let .biometricChanged(username, password):
                    biometricEmail = username
                    biometricPassword = password
                    reportSuccess("Biometric credentials retrieved into the secure fields.")
            }
        } catch {
            report(error, action: "retrieving biometric credentials")
        }
    }

    func forgetBiometricCredentials() {
        makeBiometricService().forget()
        biometricPassword = ""
        reportSuccess("Biometric credentials deleted.")
    }

    private func makeBiometricService() -> BiometricService {
        BiometricService(
            service: service,
            localAuthenticationService: LocalAuthenticationService(
                reason: "Authenticate to access your Lockbox example credentials."
            )
        )
    }

    private func reportSuccess(_ message: String) {
        status = message
        isError = false
    }

    private func reportError(_ message: String) {
        status = message
        isError = true
    }

    private func report(_ error: Error, action: String) {
        let message = (error as NSError).localizedDescription
        reportError("Error \(action): \(message)")
    }
}
