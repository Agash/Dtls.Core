using System.Security.Cryptography;
using Dtls.Core.Crypto;
using Dtls.Core.Handshake;
using Dtls.Core.Records;

namespace Dtls.Core.Protocol;

// The server's side of the handshake (RFC 6347 §4.2.4 flights 2, 4 and 6).
internal sealed partial class DtlsProtocol
{
    private const int CookieLength = 32;

    // Keys the cookie so only this server can have made it; a cookie is valid for this connection's
    // lifetime.
    private byte[]? _cookieSecret;
    private List<SignatureScheme> _peerSignatureSchemes = [];
    private NamedGroup _group;

    // Before the client has proven its address, a server keeps no state for it beyond the ClientHello
    // being reassembled (RFC 6347 §4.2.1): a ClientHello without a valid cookie is answered with a
    // HelloVerifyRequest and forgotten.
    private void ReceiveClientHelloStatelessly(
        ushort epoch,
        ulong recordSequence,
        ReadOnlySpan<byte> record
    )
    {
        if (epoch != 0)
        {
            return;
        }

        while (HandshakeFragment.TryReadNext(ref record, out HandshakeFragment fragment))
        {
            if (fragment.Type != HandshakeType.ClientHello)
            {
                continue;
            }

            // A ClientHello with another message_seq starts over: it is a new or retransmitted one.
            if (fragment.MessageSeq != _reassembler.Next)
            {
                _reassembler.Restart(fragment.MessageSeq);
            }

            _ = _reassembler.Add(fragment, authenticated: false);
            if (_reassembler.TryDequeue(out HandshakeMessage message))
            {
                ReceiveClientHelloCandidate(message, recordSequence);
                return;
            }
        }
    }

    private void ReceiveClientHelloCandidate(HandshakeMessage message, ulong recordSequence)
    {
        ClientHello hello;
        try
        {
            hello = ClientHello.Decode(message.Body);
        }
        catch (DtlsException error)
        {
            // Deliberately not fatal: nothing from this address is authenticated yet, so a malformed
            // ClientHello is dropped like any unreadable datagram.
            LogClientHelloDropped(error.Message);
            _reassembler.Restart(message.MessageSeq);
            return;
        }

        // A DTLS 1.3 handshake exchanges its cookie in a HelloRetryRequest instead (RFC 9147 §5.1).
        if (Offers13(hello))
        {
            ServerReceive(message);
            return;
        }

        _cookieSecret ??= RandomNumberGenerator.GetBytes(32);
        Span<byte> expected = stackalloc byte[CookieLength];
        Cookie(hello, expected);
        if (
            hello.Cookie.Length == CookieLength
            && CryptographicOperations.FixedTimeEquals(expected, hello.Cookie)
        )
        {
            ServerReceive(message);
            return;
        }

        // Forget the ClientHello, ready for the next one. The HelloVerifyRequest reuses its message and
        // record sequence numbers, so a server needs no state to answer (RFC 6347 §4.2.1, §4.2.2).
        _reassembler.Restart(checked((ushort)(message.MessageSeq + 1)));
        _scratch.Clear();
        new HelloVerifyRequest(expected.ToArray()).Encode(_scratch);
        HandshakeMessage request = new(
            HandshakeType.HelloVerifyRequest,
            message.MessageSeq,
            _scratch.ToArray()
        );
        _records.AdvanceSequence(0, recordSequence);
        Flight flight = new();
        flight.AddMessage(0, request);
        Transmit(flight);
        LogCookieSent();
    }

    // HMAC over what identifies the ClientHello: its random, session id and cipher suites.
    private void Cookie(ClientHello hello, Span<byte> destination)
    {
        using IncrementalHash hmac = IncrementalHash.CreateHMAC(
            HashAlgorithmName.SHA256,
            _cookieSecret!
        );
        hmac.AppendData(hello.Random);
        hmac.AppendData(hello.SessionId);
        Span<byte> suite = stackalloc byte[2];
        foreach (ushort value in hello.CipherSuites)
        {
            suite[0] = (byte)(value >> 8);
            suite[1] = (byte)value;
            hmac.AppendData(suite);
        }

        _ = hmac.GetHashAndReset(destination);
    }

    private void ServerReceive(HandshakeMessage message)
    {
        switch (_step, message.Type)
        {
            case (Step.ClientHello, HandshakeType.ClientHello):
                ClientHello clientHello = ClientHello.Decode(message.Body);
                if (Offers13(clientHello))
                {
                    _version = DtlsProtocols.Dtls13;
                    ReceiveClientHello13(message, clientHello);
                    return;
                }

                RequireVersion(DtlsProtocols.Dtls12);
                _version = DtlsProtocols.Dtls12;
                if (_settings.Allows13)
                {
                    // A server that speaks DTLS 1.3 marks a DTLS 1.2 ServerHello (RFC 8446 §4.1.3).
                    Messages13.DowngradeSentinel.CopyTo(_localRandom.AsSpan(24));
                }

                _transcript.Add(message);
                _sendSequence = message.MessageSeq;
                ReceiveClientHello(clientHello);
                SendServerHelloFlight();
                _step = _settings.ClientCertificateRequired
                    ? Step.ClientCertificate
                    : Step.ClientKeyExchange;
                return;
            case (Step.ClientCertificate, HandshakeType.Certificate):
                _transcript.Add(message);
                CertificateMessage certificate = CertificateMessage.Decode(message.Body);
                if (certificate.Chain.IsEmpty)
                {
                    throw DtlsException.HandshakeFailure(
                        "the client sent no certificate, and one is required"
                    );
                }

                AcceptRemoteCertificate(certificate);
                _step = Step.ClientKeyExchange;
                return;
            case (Step.ClientKeyExchange, HandshakeType.ClientKeyExchange):
                _transcript.Add(message);
                _premasterSecret = _keyShare!.DeriveSecret(
                    ClientKeyExchange.Decode(message.Body).PublicKey
                );
                DeriveKeys();
                if (_remoteCertificate is not null)
                {
                    _step = Step.CertificateVerify;
                }
                else
                {
                    ExpectChangeCipherSpec();
                }

                return;
            case (Step.CertificateVerify, HandshakeType.CertificateVerify):
                CertificateVerify verify = CertificateVerify.Decode(message.Body);
                if (
                    !Signatures.Verify(
                        _remoteCertificate!,
                        verify.Scheme,
                        _transcript.Bytes,
                        verify.Signature
                    )
                )
                {
                    throw DtlsException.DecryptError("the client's CertificateVerify");
                }

                _transcript.Add(message);
                ExpectChangeCipherSpec();
                return;
            case (Step.Finished, HandshakeType.Finished):
                ReceiveFinished(message, fromClient: true);
                SendServerFinishedFlight();
                Connected();
                return;
            default:
                throw DtlsException.Unexpected($"{message.Type} where the server expected {_step}");
        }
    }

    private void ReceiveClientHello(ClientHello hello)
    {
        // DTLS versions count down: a client whose highest version is above 0xFEFD offers only DTLS 1.0.
        if (hello.Version > ProtocolVersion.Dtls12)
        {
            throw new DtlsException(
                DtlsAlert.ProtocolVersion,
                isRemote: false,
                $"The client offers version 0x{hello.Version:X4}; Dtls.Core speaks DTLS 1.2."
            );
        }

        _peerRandom = hello.Random;
        Extensions extensions = hello.Extensions;
        _suite = _settings.CipherSuites.FirstOrDefault(s =>
            hello.CipherSuites.Contains((ushort)s.Suite)
        );
        if (_suite.Suite == default)
        {
            throw DtlsException.HandshakeFailure(
                "the client offers no cipher suite this server uses"
            );
        }

        _extendedMasterSecret = extensions.Contains(ExtensionType.ExtendedMasterSecret);
        if (!_extendedMasterSecret && _settings.RequireExtendedMasterSecret)
        {
            throw DtlsException.HandshakeFailure(
                "the client does not offer the extended master secret"
            );
        }

        if (
            extensions.TryGet(ExtensionType.RenegotiationInfo, out ReadOnlySpan<byte> renegotiation)
            && !HelloExtensions.IsEmptyRenegotiationInfo(renegotiation)
        )
        {
            throw DtlsException.HandshakeFailure("the client's renegotiation_info is not empty");
        }

        if (
            extensions.TryGet(ExtensionType.EcPointFormats, out ReadOnlySpan<byte> formats)
            && !HelloExtensions.OffersUncompressedPoints(formats)
        )
        {
            throw DtlsException.IllegalParameter("the client does not accept uncompressed points");
        }

        // A client that names no groups accepts any (RFC 8422 §4); the server's preference decides.
        List<NamedGroup>? groups = extensions.TryGet(
            ExtensionType.SupportedGroups,
            out ReadOnlySpan<byte> groupData
        )
            ? HelloExtensions.ReadSupportedGroups(groupData)
            : null;
        _group = KeyShare.SupportedGroups.FirstOrDefault(g => groups is null || groups.Contains(g));
        if (_group == default)
        {
            throw DtlsException.HandshakeFailure(
                "the client offers no elliptic curve group this server uses"
            );
        }

        if (extensions.TryGet(ExtensionType.SignatureAlgorithms, out ReadOnlySpan<byte> schemes))
        {
            _peerSignatureSchemes = HelloExtensions.ReadSignatureAlgorithms(schemes);
        }

        SelectSrtpAndApplicationProtocol(extensions);
    }

    // DTLS-SRTP and ALPN from the client's offers, by this server's preference (RFC 5764 §4.1.1, RFC
    // 7301 §3.2). A server that asks for DTLS-SRTP requires it.
    private void SelectSrtpAndApplicationProtocol(Extensions extensions)
    {
        SelectConnectionId(extensions);
        AcceptRecordSizeLimit(extensions);
        if (!_settings.SrtpProfiles.IsEmpty)
        {
            List<SrtpProtectionProfile> offered = extensions.TryGet(
                ExtensionType.UseSrtp,
                out ReadOnlySpan<byte> srtp
            )
                ? HelloExtensions.ReadUseSrtp(srtp)
                : [];
            SrtpProtectionProfile chosen = _settings.SrtpProfiles.FirstOrDefault(offered.Contains);
            _srtpProfile =
                chosen != default
                    ? chosen
                    : throw DtlsException.HandshakeFailure(
                        "the client offers no SRTP protection profile this server uses"
                    );
        }

        if (
            !_settings.ApplicationProtocols.IsEmpty
            && extensions.TryGet(
                ExtensionType.ApplicationLayerProtocolNegotiation,
                out ReadOnlySpan<byte> alpn
            )
        )
        {
            List<System.Net.Security.SslApplicationProtocol> offered =
                HelloExtensions.ReadApplicationProtocols(alpn);
            NegotiatedApplicationProtocol = _settings.ApplicationProtocols.FirstOrDefault(
                offered.Contains
            );
            if (NegotiatedApplicationProtocol == default)
            {
                throw new DtlsException(
                    DtlsAlert.NoApplicationProtocol,
                    isRemote: false,
                    "The client offers no application protocol this server uses."
                );
            }
        }
    }

    // Flight 4: ServerHello, Certificate, ServerKeyExchange, CertificateRequest when the client must
    // authenticate, and ServerHelloDone.
    private void SendServerHelloFlight()
    {
        LocalCredential credential = _settings.Credential!;
        Extensions extensions = new Extensions()
            .Add(ExtensionType.RenegotiationInfo, HelloExtensions.EmptyRenegotiationInfo())
            .Add(ExtensionType.EcPointFormats, HelloExtensions.PointFormats());
        if (_extendedMasterSecret)
        {
            _ = extensions.Add(ExtensionType.ExtendedMasterSecret, []);
        }

        if (_srtpProfile is { } profile)
        {
            _ = extensions.Add(ExtensionType.UseSrtp, HelloExtensions.UseSrtp([profile]));
        }

        if (NegotiatedApplicationProtocol != default)
        {
            _ = extensions.Add(
                ExtensionType.ApplicationLayerProtocolNegotiation,
                HelloExtensions.ApplicationProtocols([NegotiatedApplicationProtocol])
            );
        }

        AnswerConnectionId(extensions);
        AnswerRecordSizeLimit(extensions);

        Flight flight = new();
        Add(
            flight,
            NewMessage(
                HandshakeType.ServerHello,
                new ServerHello(_localRandom, [], (ushort)_suite.Suite, extensions).Encode
            )
        );
        Add(
            flight,
            NewMessage(HandshakeType.Certificate, new CertificateMessage(credential.Chain).Encode)
        );

        _keyShare = KeyShare.Create(_group);
        SignatureScheme scheme = Signatures.Choose(credential, _peerSignatureSchemes);
        ServerKeyExchange unsigned = new(_group, _keyShare.PublicKey, scheme, []);
        byte[] parameters = unsigned.SignedParameters();
        byte[] signature = Signatures.Sign(
            credential,
            scheme,
            [.. _peerRandom!, .. _localRandom, .. parameters]
        );
        Add(
            flight,
            NewMessage(
                HandshakeType.ServerKeyExchange,
                (unsigned with { Signature = signature }).Encode
            )
        );

        if (_settings.ClientCertificateRequired)
        {
            CertificateRequest request = new(
                [ClientCertificateType.EcdsaSign, ClientCertificateType.RsaSign],
                Signatures.Accepted
            );
            Add(flight, NewMessage(HandshakeType.CertificateRequest, request.Encode));
        }

        Add(flight, NewMessage(HandshakeType.ServerHelloDone, static _ => { }));
        SendFlight(flight, timed: true);
    }

    // Flight 6: ChangeCipherSpec and the server's Finished, the last of the handshake. It is not timed;
    // it is sent again only when the client's whole flight 5 arrives again.
    private void SendServerFinishedFlight()
    {
        _records.InstallWrite(_pendingWrite!);
        _pendingWrite = null;
        Flight flight = new();
        flight.AddChangeCipherSpec(0);
        flight.AddMessage(1, FinishedMessage(fromClient: false));
        SendFlight(flight, timed: false);
    }

    private void ExpectChangeCipherSpec() => _step = Step.Finished;

    private void Add(Flight flight, HandshakeMessage message)
    {
        _transcript.Add(message);
        flight.AddMessage(0, message);
    }
}
