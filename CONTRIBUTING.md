# Contributing

Thanks for your interest in Dtls.Core.

## Building

```sh
git clone https://github.com/Agash/Dtls.Core
cd Dtls.Core
dotnet build Dtls.Core.slnx
dotnet test --solution Dtls.Core.slnx
```

The build targets .NET 11 and treats warnings as errors.

## How it is built

The public API is at the top level: `DtlsConnection` drives the protocol over an `IDatagramTransport`.
The protocol itself is in `src/Dtls.Core/Protocol` (`DtlsProtocol`, which does no I/O: it is handed
datagrams and the time and queues datagrams to send), the record layer in `Records`, handshake messages,
framing and reassembly in `Handshake`, and the key schedule, PRF and signatures in `Crypto`.

The RFCs are the specification. Where they leave room, the behaviour follows
[BouncyCastle's DTLS](https://github.com/bcgit/bc-csharp/tree/master/crypto/src/tls) (retransmitting
only when the peer's whole flight arrives again, ignoring malformed unencrypted fragments) and .NET's
`SslStream` and `QuicConnection` (options, validation, exceptions). `external/` is gitignored and holds
local checkouts of these and the RFCs for reference.

## Tests

`HandshakeTests` run both sides in memory, including over a path that loses datagrams. The interop
tests run each platform's own DTLS against Dtls.Core and compare the keying material both export:

- `OpenSslInteropTests`: OpenSSL's `s_server` and `s_client` (`DTLS_OPENSSL` names the binary; on
  macOS Homebrew's `openssl@3` is used, since `/usr/bin/openssl` is LibreSSL, which has its own test).
  On Windows the `s_server` cases are inconclusive: the Windows builds of `s_server` do not serve DTLS
  when stdin is a pipe.
- `SchannelInteropTests`: Schannel through SSPI (`SchannelPeer`), on Windows.
- `NetworkFrameworkInteropTests`: Network.framework through `tests/NetworkFrameworkPeer/peer.swift`, run
  with `swift` on macOS.
- `WolfSslInteropTests`: wolfSSL's example client and server, the DTLS 1.3 peer, when
  `DTLS_WOLFSSL_EXAMPLES` names the examples directory of a wolfSSL built with `--enable-dtls
  --enable-dtls13 --enable-srtp --enable-dtls-frag-ch --enable-keying-material --enable-opensslextra`
  (CI builds it on Linux).

## Pull requests

Keep changes focused. Make sure the build is clean and the tests pass.

## License

By contributing you agree that your contributions are licensed under the MIT License.

## House rules

- **Warnings are errors.** Fix the diagnostic rather than suppressing it; a `NoWarn` or `#pragma` needs
  a comment saying why the rule genuinely does not apply.
- **Nullable reference types are enabled** everywhere. No `!` without a reason.
- **All I/O is async**, with a `CancellationToken` accepted and propagated.
- **Public API carries XML documentation.**
- **The package is trim- and AOT-clean.** `IsAotCompatible` is set, and CI publishes and runs a Native
  AOT program.
- **Nothing a peer sends is trusted.** Every length is checked against the bytes present, nothing is
  buffered without a bound, and unauthenticated input is dropped rather than allowed to end a
  connection.

## Tests

- Name tests `{Method}_{Scenario}_{ExpectedResult}`.
- Prefer the purpose-built MSTest assertions over hand-rolled equality checks.
