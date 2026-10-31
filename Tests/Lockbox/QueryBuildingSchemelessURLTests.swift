#if os(macOS) || os(iOS)
    import Foundation
    @testable import Lockbox
    import Testing

    @Suite(.serialized) struct QueryBuildingSchemelessURLTests {

        /// The identity attributes a URL maps to.
        struct Expected: Sendable, CustomTestStringConvertible {
            let input: String
            let internetProtocol: String?
            let server: String?
            let port: Int?
            let path: String

            var testDescription: String {
                input
            }

            init(_ input: String, _ internetProtocol: CFString?, server: String?, port: Int?, path: String) {
                self.input = input
                self.internetProtocol = internetProtocol as String?
                self.server = server
                self.port = port
                self.path = path
            }
        }

        /// Input without a scheme, which Foundation parses as a path, or with a host in the
        /// scheme position, such as `example.com:8443/login`.
        static let schemeless: [Expected] = [
            Expected("example.com", kSecAttrProtocolHTTPS, server: "example.com", port: 443, path: "/"),
            Expected("example.com/login", kSecAttrProtocolHTTPS, server: "example.com", port: 443, path: "/login"),
            Expected("example.com:8443/login", kSecAttrProtocolHTTPS, server: "example.com", port: 8443, path: "/login"),
            Expected("example.com:8443", kSecAttrProtocolHTTPS, server: "example.com", port: 8443, path: "/"),
            Expected("localhost", kSecAttrProtocolHTTPS, server: "localhost", port: 443, path: "/"),
            Expected("localhost:8080", kSecAttrProtocolHTTPS, server: "localhost", port: 8080, path: "/"),
            Expected("localhost:8080/x", kSecAttrProtocolHTTPS, server: "localhost", port: 8080, path: "/x"),
            Expected("Example.COM:8443/Login", kSecAttrProtocolHTTPS, server: "example.com", port: 8443, path: "/Login"),
            Expected("example.com/path?query=1", kSecAttrProtocolHTTPS, server: "example.com", port: 443, path: "/path"),
            Expected("example.com?query=1", kSecAttrProtocolHTTPS, server: "example.com", port: 443, path: "/"),
            Expected("[::1]", kSecAttrProtocolHTTPS, server: "::1", port: 443, path: "/"),
            Expected("[::1]:8080/x", kSecAttrProtocolHTTPS, server: "::1", port: 8080, path: "/x"),
            // A scheme-like word followed by a port is read as a host and port.
            Expected("tel:5551", kSecAttrProtocolHTTPS, server: "tel", port: 5551, path: "/")
        ]

        /// Input that already has a scheme, or has no host to find, maps as it did before.
        static let unchanged: [Expected] = [
            Expected("https://example.com:8443/login", kSecAttrProtocolHTTPS, server: "example.com", port: 8443, path: "/login"),
            Expected("http://example.com", kSecAttrProtocolHTTP, server: "example.com", port: 80, path: "/"),
            Expected("ftp://files.example.com/pub", kSecAttrProtocolFTP, server: "files.example.com", port: nil, path: "/pub"),
            Expected("ssh://host", kSecAttrProtocolSSH, server: "host", port: nil, path: "/"),
            Expected("ssh://host:22", kSecAttrProtocolSSH, server: "host", port: 22, path: "/"),
            Expected("custom://s.example.com:9000/p", nil, server: "s.example.com", port: 9000, path: "/p"),
            Expected("mailto:a@b.com", nil, server: nil, port: nil, path: "a@b.com"),
            Expected("tel:5551234", nil, server: nil, port: nil, path: "5551234"),
            // Not ports: out of range, or followed by something other than `/`, `?`, `#`.
            Expected("foo:99999", nil, server: nil, port: nil, path: "99999"),
            Expected("foo:80x", nil, server: nil, port: nil, path: "80x"),
            Expected("file:///tmp/x", nil, server: nil, port: nil, path: "/tmp/x"),
            Expected("/path", kSecAttrProtocolHTTPS, server: nil, port: 443, path: "/path"),
            // Relative paths have no host.
            Expected("./a", kSecAttrProtocolHTTPS, server: nil, port: 443, path: "./a"),
            Expected("../a", kSecAttrProtocolHTTPS, server: nil, port: 443, path: "../a"),
            // A recognised scheme is never a host, even when digits follow it.
            Expected("http:80", kSecAttrProtocolHTTP, server: nil, port: 80, path: "80"),
            Expected("HTTP:80", kSecAttrProtocolHTTP, server: nil, port: 80, path: "80"),
            Expected("ssh:22", kSecAttrProtocolSSH, server: nil, port: nil, path: "22")
        ]

        private func expectQuery(_ query: [String: AnyObject], matches expected: Expected) {
            #expect(query[kSecAttrProtocol as String] as? String == expected.internetProtocol, "protocol")
            #expect(query[kSecAttrServer as String] as? String == expected.server, "server")
            #expect((query[kSecAttrPort as String] as? NSNumber)?.intValue == expected.port, "port")
            #expect(query[kSecAttrPath as String] as? String == expected.path, "path")
        }

        private func check(_ expected: Expected) throws {
            let url = try #require(URL(string: expected.input))
            let urlQuery = try #require([KeychainCriterion.url(url)].query as? [String: AnyObject])
            let password = KeychainPassword.internet(url: url, account: "user")
            let passwordQuery = try #require(password.criteria.query as? [String: AnyObject])

            expectQuery(urlQuery, matches: expected)
            expectQuery(passwordQuery, matches: expected)
        }

        @Test(arguments: schemeless)
        func schemelessInputIsMappedAsHTTPS(expected: Expected) throws {
            try check(expected)
        }

        @Test(arguments: unchanged)
        func inputWithASchemeMapsAsBefore(expected: Expected) throws {
            try check(expected)
        }
    }
#endif
