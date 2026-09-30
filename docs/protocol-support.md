# Protocol support and invariants

## Supported

| Area | DTLS 1.3 (RFC 9147) | DTLS 1.2 (RFC 6347) |
| --- | --- | --- |
| Key exchange | ECDHE on P-256, P-384 | ECDHE on P-256, P-384 |
| Cipher suites | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | ECDHE-ECDSA/RSA with AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| Authentication | X.509 certificates, both sides; ECDSA (curve-bound), RSA-PSS | X.509 certificates, both sides; ECDSA, RSA-PSS, RSA PKCS #1 |
| Address validation | Stateless HelloRetryRequest cookie | Stateless HelloVerifyRequest cookie |
| Reliability | Flight retransmission with ACKs; fragmentation to the path MTU | Flight retransmission; fragmentation to the path MTU |
| After the handshake | KeyUpdate (both ways), NewSessionTicket acknowledged and ignored | No renegotiation (refused with no_renegotiation) |
| Extensions | use_srtp, ALPN, supported_groups, signature_algorithms, cookie | use_srtp, ALPN, extended master secret, renegotiation_info |
| Keys out | RFC 8446 exporter; DTLS-SRTP keying material | RFC 5705 exporter; DTLS-SRTP keying material |

## Not supported, deliberately

- **0-RTT (early data).** DTLS makes replay of early data easy; it is not offered or accepted.
- **Session resumption and PSK**, **raw public keys (RFC 7250)**, **connection IDs (RFC 9146)**:
  not yet. A record with a connection ID is dropped.
- **DTLS 1.0**: deprecated by RFC 8996.
- **Renegotiation and compression**: never negotiated.

## Invariants

These hold for every datagram, whatever it contains, and the tests check them (`AdversarialTests`
feeds thousands of random and mutated datagrams during and after handshakes):

- **An unauthenticated datagram cannot end a connection.** Records that fail to parse, authenticate or
  belong to a readable epoch are dropped and counted. Unprotected handshake messages that are
  malformed, out of place or contradict what came before are dropped and the handshake waits for the
  genuine retransmission; only a well-formed negotiation that fails (no shared version, suite, group,
  profile or application protocol, or a refused certificate) ends it. A handshake that then runs out
  of time reports the last message it refused.
- **Replay protection moves only on authenticated records.** The window of an epoch advances after a
  record authenticates, never on unprotected ones, so a forged sequence number cannot make genuine
  records look old.
- **Nothing a peer declares is allocated before it is checked.** Record lengths are checked against
  the bytes present, handshake message lengths against `MaximumHandshakeMessageSize` before any buffer
  exists, and at most 8 messages are reassembled at once.
- **Fragments may overlap but not disagree.** A contradicting fragment in an authenticated record is an
  illegal_parameter; in an unprotected one it starts the message over, since either may be forged.
- **Epochs and sequence numbers never wrap.** A 48-bit record sequence number, a 16-bit message_seq or
  an epoch that would wrap ends the connection with a DtlsException. Dtls.Core counts epochs in 16 bits,
  which allows 65,532 DTLS 1.3 key updates.
- **DTLS 1.3 post-handshake messages come under the application keys.** Once connected, epoch 2
  carries only retransmissions of the handshake.
- **DTLS 1.3 keys have a forgery budget.** Past 2^36 records failing to authenticate under one key
  (RFC 9147 §4.5.3), the connection ends.
- **Secrets live as long as they are used.** Handshake traffic secrets are zeroed once both Finished
  messages are done; everything else when the connection is disposed.
- **A server keeps no state before the cookie.** Both versions answer a ClientHello without a valid
  cookie from what it carries alone.

## Closing

- `CloseAsync` sends close_notify and stops the connection; it does not wait for the peer's.
  `DisposeAsync` does the same if the connection is still open, then releases it.
- After the peer's close_notify, `ReceiveAsync` returns what was already queued, then 0; `SendAsync`
  throws a `DtlsException` whose `IsRemote` is true.
- A lost close_notify is not retransmitted (DTLS has no reliable close): the peer notices through its
  own timeouts.
- After a failure, both throw the failure.
