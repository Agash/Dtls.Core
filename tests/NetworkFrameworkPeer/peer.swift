// Apple's DTLS 1.2 (Network.framework) as a peer for Dtls.Core's interop tests.
//
//   swift peer.swift client <port> <identity.p12> <password>
//   swift peer.swift server <identity.p12> <password>
//
// It authenticates with the PKCS #12 identity, accepts any peer certificate (the test checks
// fingerprints on its side), and prints what the test compares:
//   READY <port>          (server) listening
//   CIPHER <suite>        the negotiated cipher suite's IANA number
//   PEER <hex>            the peer's certificate, DER
//   KEY <hex>             60 bytes from sec_protocol_metadata_create_secret, label EXTRACTOR-dtls_srtp
//   RECV <text>           a datagram received
// then sends "from-network-framework" and waits for one datagram before exiting.

import Foundation
import Network
import Security

let arguments = CommandLine.arguments
let mode = arguments[1]
let identityPath = mode == "client" ? arguments[3] : arguments[2]
let password = mode == "client" ? arguments[4] : arguments[3]
let queue = DispatchQueue(label: "peer")

func fail(_ message: String) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(1)
}

func hex(_ data: Data) -> String { data.map { String(format: "%02X", $0) }.joined() }

func loadIdentity() -> sec_identity_t {
    guard let p12 = FileManager.default.contents(atPath: identityPath) else { fail("cannot read \(identityPath)") }
    var items: CFArray?
    // In memory only: the peer runs without a login keychain (over SSH, in CI).
    let options: [String: Any] = [kSecImportExportPassphrase as String: password, kSecImportToMemoryOnly as String: true]
    let status = SecPKCS12Import(p12 as CFData, options as CFDictionary, &items)
    guard status == errSecSuccess, let first = (items as? [[String: Any]])?.first,
          let identity = first[kSecImportItemIdentity as String] else { fail("SecPKCS12Import failed: \(status)") }
    return sec_identity_create(identity as! SecIdentity)!
}

func parameters(server: Bool) -> NWParameters {
    let tls = NWProtocolTLS.Options()
    let options = tls.securityProtocolOptions
    sec_protocol_options_set_min_tls_protocol_version(options, .DTLSv12)
    sec_protocol_options_set_max_tls_protocol_version(options, .DTLSv12)
    sec_protocol_options_set_local_identity(options, loadIdentity())
    sec_protocol_options_set_peer_authentication_required(options, true)
    sec_protocol_options_set_verify_block(options, { metadata, _, complete in
        sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
            let der = SecCertificateCopyData(sec_certificate_copy_ref(certificate).takeRetainedValue()) as Data
            if !printedPeer { printedPeer = true; print("PEER \(hex(der))") }
        }
        complete(true)
    }, queue)
    return NWParameters(dtls: tls, udp: NWProtocolUDP.Options())
}

var printedPeer = false

func run(_ connection: NWConnection) {
    connection.stateUpdateHandler = { state in
        switch state {
        case .ready:
            guard let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
                fail("no TLS metadata")
            }
            let security = metadata.securityProtocolMetadata
            print("CIPHER \(sec_protocol_metadata_get_negotiated_tls_ciphersuite(security).rawValue)")
            let label = "EXTRACTOR-dtls_srtp"
            guard let secret = label.withCString({ sec_protocol_metadata_create_secret(security, label.utf8.count, $0, 60) }) else {
                fail("the exporter failed")
            }
            let key = Data(secret as DispatchData)
            print("KEY \(hex(key))")
            connection.receiveMessage { data, _, _, error in
                if let error { fail("receive failed: \(error)") }
                print("RECV \(String(decoding: data ?? Data(), as: UTF8.self))")
                connection.send(content: "from-network-framework".data(using: .utf8), completion: .contentProcessed { _ in
                    queue.asyncAfter(deadline: .now() + 1) { exit(0) }
                })
            }
        case .failed(let error):
            fail("connection failed: \(error)")
        default:
            break
        }
    }
    connection.start(queue: queue)
}

if mode == "client" {
    let port = NWEndpoint.Port(rawValue: UInt16(arguments[2])!)!
    run(NWConnection(host: "127.0.0.1", port: port, using: parameters(server: false)))
} else {
    let listener = try! NWListener(using: parameters(server: true), on: .any)
    listener.stateUpdateHandler = { state in
        if case .ready = state { print("READY \(listener.port!.rawValue)") }
        if case .failed(let error) = state { fail("listener failed: \(error)") }
    }
    listener.newConnectionHandler = { connection in run(connection) }
    listener.start(queue: queue)
}

setvbuf(stdout, nil, _IOLBF, 0)
dispatchMain()
