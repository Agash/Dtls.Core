# Dtls.NET

[![NuGet](https://img.shields.io/nuget/v/Dtls.NET.svg)](https://www.nuget.org/packages/Dtls.NET)
[![build](https://github.com/Agash/Dtls.NET/actions/workflows/build.yml/badge.svg)](https://github.com/Agash/Dtls.NET/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

DTLS 1.2 ([RFC 6347](https://www.rfc-editor.org/rfc/rfc6347)) for .NET 11, on the platform's own
cryptography: an authenticated, encrypted datagram channel to one peer, and with DTLS-SRTP
([RFC 5764](https://www.rfc-editor.org/rfc/rfc5764)) the keys for its media. It is what WebRTC runs its
handshake with, and it interoperates with OpenSSL in both directions.

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
- Logs through `Microsoft.Extensions.Logging` and runs on a `TimeProvider`.

> **Alpha.** Expect breaking changes before 1.0.

## Install

```sh
dotnet add package Dtls.NET
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
`UdpDatagramTransport` wraps a connected UDP socket; an ICE implementation, which demultiplexes DTLS
from SRTP and STUN on one socket, implements the interface to hand the connection its DTLS datagrams.

```csharp
using UdpDatagramTransport transport = UdpDatagramTransport.Connect(new IPEndPoint(address, port));
```

## Data

DTLS keeps datagram boundaries: each `SendAsync` arrives as one `ReceiveAsync`, whole, or not at all,
in any order. `MaximumApplicationDataSize` is the most one datagram carries. The connection reads the
transport in the background, so it answers the peer's retransmissions and alerts whether or not the
application reads; `ReceiveAsync` returns 0 once the peer has closed the connection.

`ExportKeyingMaterial` is the RFC 5705 exporter, for protocols that derive their own keys from the
handshake.

## Errors

A handshake that fails throws `AuthenticationException` with a `DtlsException` inside, as `SslStream`
does; `DtlsException.Alert` is the alert, and `IsRemote` says whether the peer sent it. A handshake that
does not finish within `HandshakeTimeout` throws `TimeoutException`. Once connected, a failure is a
`DtlsException`, which is an `IOException`.

## What it implements

| | |
| --- | --- |
| Version | DTLS 1.2 |
| Cipher suites | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `..._AES_256_GCM_SHA384`, `..._CHACHA20_POLY1305_SHA256`, and the `ECDHE_RSA` equivalents |
| Groups | P-256, P-384 |
| Signatures | ECDSA with SHA-256 and SHA-384, RSA-PSS, RSA PKCS #1 |
| Extensions | extended master secret (required by default), `use_srtp`, ALPN, `renegotiation_info` |
| Not implemented | session resumption, renegotiation (refused), PSK, DTLS 1.0 and 1.3, compression |

## Building

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE).
