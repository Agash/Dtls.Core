# Dtls.Core

[![NuGet](https://img.shields.io/nuget/v/Dtls.Core.svg)](https://www.nuget.org/packages/Dtls.Core)
[![build](https://github.com/Agash/Dtls.Core/actions/workflows/build.yml/badge.svg)](https://github.com/Agash/Dtls.Core/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

DTLS 1.2 ([RFC 6347](https://www.rfc-editor.org/rfc/rfc6347)) and DTLS 1.3
([RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)) for .NET 11, on the platform's own cryptography:
an authenticated, encrypted datagram channel to one peer, and with DTLS-SRTP
([RFC 5764](https://www.rfc-editor.org/rfc/rfc5764)) the keys for its media. It is what WebRTC runs its
handshake with, and it interoperates with OpenSSL, Schannel, Network.framework and wolfSSL in both
directions.

The API follows `QuicConnection` and `SslStream`: a connection is made with `ConnectAsync` or
`AcceptAsync`, configured with `SslClientAuthenticationOptions` or `SslServerAuthenticationOptions`,
and certificates are validated with a `RemoteCertificateValidationCallback`.

- Native AOT compatible, with no native dependencies: AES-GCM, ChaCha20-Poly1305, ECDH and the
  signatures come from `System.Security.Cryptography`.
- Near zero allocation on the data path: records are opened in place and datagrams are built in pooled
  buffers.
- The handshake retransmits, fragments to the path's MTU, exchanges a cookie before doing any work for
  an unverified address, and drops what does not authenticate or is replayed rather than letting it end
  the connection.
- Connection IDs keep a connection alive when the peer's address changes, as a phone moving from Wi-Fi to
  cellular or a NAT rebinding does, and record size limits let a constrained receiver bound what it is
  sent.
- Logs through `Microsoft.Extensions.Logging` and runs on a `TimeProvider`.

> **Alpha.** Expect breaking changes before 1.0.

## Install

```sh
dotnet add package Dtls.Core
```

## WebRTC-style peers

Each side has a self-signed certificate, and the peers learn each other's fingerprint from signalling
(SDP's `a=fingerprint`). The fingerprint is what authenticates the peer:

```csharp
using X509Certificate2 certificate = DtlsCertificates.CreateSelfSigned();
DtlsFingerprint mine = DtlsFingerprint.Compute(certificate);        // signal mine.ToString()
DtlsFingerprint theirs = DtlsFingerprint.Parse(remoteSdpFingerprint);

await using DtlsConnection connection = await DtlsConnection.ConnectAsync(
    transport,
    new DtlsClientConnectionOptions
    {
        ClientAuthenticationOptions = new SslClientAuthenticationOptions
        {
            ClientCertificates = [certificate],
            RemoteCertificateValidationCallback = theirs.CreateValidationCallback(),
        },
        SrtpProtectionProfiles = [SrtpProtectionProfile.AeadAes128Gcm, SrtpProtectionProfile.Aes128CmHmacSha180],
    },
    cancellationToken);

SrtpKeyingMaterial keys = connection.SrtpKeyingMaterial!;
```

The server side is the same with `DtlsConnection.AcceptAsync`, `DtlsServerConnectionOptions` and
`SslServerAuthenticationOptions` (`ServerCertificate`, and `ClientCertificateRequired = true` so the
client authenticates too).

## Transports

A connection runs over an `IDatagramTransport`: send and receive whole datagrams to and from one peer.
`UdpDatagramTransport` wraps a UDP socket; an ICE implementation, which demultiplexes DTLS from SRTP and
STUN on one socket, implements the interface to hand the connection its DTLS datagrams.

```csharp
// Connected to one address.
using UdpDatagramTransport transport = UdpDatagramTransport.Connect(new IPEndPoint(address, port));

// Bound but not connected: receives from any address, so the connection can follow a peer that moves.
using UdpDatagramTransport mobile = UdpDatagramTransport.Bind(new IPEndPoint(address, port));
```

## Connection IDs and moving peers

With connection IDs (RFC 9146 for DTLS 1.2, RFC 9147 section 9 for DTLS 1.3) every protected record
carries an identifier the receiver chose, so the receiver recognises its peer's records from any address.
`ConnectionIdLength` sets the length this side asks for: 0 by default, which offers the extension without
asking for an identifier but still gives the peer one when it asks; null leaves the extension out.

```csharp
options.ConnectionIdLength = 8;  // ask the peer to put an 8-byte identifier in every record it sends
```

`LocalConnectionId` and `RemoteConnectionId` show what was agreed. Over a transport that implements
`IMobileDatagramTransport`, such as a bound `UdpDatagramTransport`, the connection follows the peer to a
new address when a record arrives from there that carries this side's identifier, authenticates, and is
newer than every record before it (RFC 9146 section 6), so a replayed or forged datagram cannot redirect
it.

DTLS 1.3 also changes identifiers during the connection: `IssueConnectionIdsAsync` gives the peer new
ones, to use at once or keep as spares; `RequestConnectionIdsAsync` asks the peer for spares; and
`TryUseNextConnectionId` switches to the next spare, which RFC 9147 asks for on a new path so the two
paths cannot be linked by their identifier.

## Record size limits

`RecordSizeLimit` (RFC 8449) is the most plaintext this side takes in a protected record, 16384 bytes by
default. It is always advertised, and the peer's limit, `PeerRecordSizeLimit`, bounds
`MaximumApplicationDataSize`.

## Data

DTLS keeps datagram boundaries: each `SendAsync` arrives as one `ReceiveAsync`, whole, or not at all,
in any order. `MaximumApplicationDataSize` is the most one datagram carries. The connection reads the
transport in the background, so it answers the peer's retransmissions and alerts whether or not the
application reads; `ReceiveAsync` returns 0 once the peer has closed the connection.

`ExportKeyingMaterial` is the RFC 5705 exporter, for protocols that derive their own keys from the
handshake.

## Dependency injection

`AddDtls` registers a `DtlsConnectionFactory`, which makes connections that log through the
application's `ILoggerFactory` and run on its `TimeProvider`. Options can be configured once by name:

```csharp
services.AddDtlsClient("webrtc", options =>
{
    options.ClientAuthenticationOptions = new SslClientAuthenticationOptions { ... };
    options.SrtpProtectionProfiles = [SrtpProtectionProfile.AeadAes128Gcm];
});

DtlsConnection connection = await factory.ConnectAsync(transport, "webrtc", cancellationToken);
```

## Statistics and metrics

`DtlsConnection.Statistics` counts datagrams, dropped records, authentication failures, retransmissions
and application data per connection. The meter `Dtls.Core` (for `dotnet-counters` or OpenTelemetry's
`AddMeter("Dtls.Core")`) records `dtls.handshake.duration` by version, role and outcome, and counts
retransmissions and dropped records. Nothing secret is logged or measured.

## Versions

The version is negotiated: a client offers every version in `EnabledProtocols` (DTLS 1.2 and 1.3 by
default) in one ClientHello, and the server picks the highest both allow. `NegotiatedProtocol` says
which. A server that allows DTLS 1.3 marks a DTLS 1.2 handshake (RFC 8446 §4.1.3), so a client that
also allows 1.3 detects an attacker who strips the 1.3 offer and fails rather than falling back.
Nothing retries with a lower version after a failure: that would undo the protection.

## Errors

A handshake that fails throws `AuthenticationException` with a `DtlsException` inside, as `SslStream`
does; `DtlsException.Alert` is the alert, and `IsRemote` says whether the peer sent it. A handshake that
does not finish within `HandshakeTimeout` throws `TimeoutException`. Once connected, a failure is a
`DtlsException`, which is an `IOException`.

## What it implements

| | |
| --- | --- |
| Versions | DTLS 1.2, DTLS 1.3 |
| DTLS 1.3 cipher suites | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` |
| DTLS 1.2 cipher suites | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `..._AES_256_GCM_SHA384`, `..._CHACHA20_POLY1305_SHA256`, and the `ECDHE_RSA` equivalents |
| Groups | P-256, P-384 |
| Signatures | ECDSA with SHA-256 and SHA-384, RSA-PSS, RSA PKCS #1 (DTLS 1.2) |
| DTLS 1.3 | HelloRetryRequest with cookie, ACKs, KeyUpdate, record number encryption, NewConnectionId and RequestConnectionId |
| DTLS 1.2 | extended master secret (required by default), `renegotiation_info`, HelloVerifyRequest cookie |
| Both | `use_srtp`, ALPN, connection IDs and peer address updates, `record_size_limit`, the keying material exporter |
| Not implemented | session resumption, PSK, 0-RTT, renegotiation (refused), DTLS 1.0, compression |

## Interoperability

The tests run handshakes, compare exported keys and exchange data with the platforms' own DTLS
implementations, in both roles where the peer has them:

| Peer | Versions | Dtls.Core as client | Dtls.Core as server | DTLS-SRTP |
| --- | --- | --- | --- | --- |
| wolfSSL 5.9 (Linux) | 1.3, 1.2, and either; connection IDs in both | yes | yes | yes |
| OpenSSL 3 (Linux, macOS) | 1.2 | yes | yes | yes |
| Schannel (Windows) | 1.2 | yes | yes | yes |
| Network.framework (macOS) | 1.2 | yes | yes | not in its API |
| LibreSSL (macOS) | 1.2 | | yes, with `RequireExtendedMasterSecret` off | yes |

Against a peer that speaks only DTLS 1.2, Dtls.Core's default settings negotiate 1.2. LibreSSL has no
extended master secret, which Dtls.Core requires by default.

## Protocol support

What is and is not implemented, the invariants the tests hold the implementation to, and how a
connection closes: [docs/protocol-support.md](docs/protocol-support.md).

## Building

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE).
