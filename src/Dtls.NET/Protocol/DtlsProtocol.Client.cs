using System.Collections.Immutable;
using System.Net.Security;
using Dtls.NET.Crypto;
using Dtls.NET.Handshake;
using Dtls.NET.Records;

namespace Dtls.NET.Protocol;

// The client's side of the handshake (RFC 6347 §4.2.4 flights 1, 3 and 5).
internal sealed partial class DtlsProtocol
{
    private bool _cookieReceived;
    private CertificateRequest? _certificateRequest;

    // Flight 1 (and 3, with the server's cookie): the ClientHello. It offers every version this side
    // allows: DTLS 1.3 through supported_versions and a key share, DTLS 1.2 through the legacy fields
    // and its extensions; the server's answer decides.
    private void SendClientHello(byte[] cookie)
    {
        bool allows12 = _settings.Allows12;
        bool allows13 = _settings.Allows13;
        Extensions extensions = new Extensions()
            .Add(
                ExtensionType.SupportedGroups,
                HelloExtensions.SupportedGroups(KeyShare.SupportedGroups)
            )
            .Add(
                ExtensionType.SignatureAlgorithms,
                HelloExtensions.SignatureAlgorithms(
                    allows12 ? Signatures.Accepted : Signatures.Accepted13
                )
            );
        if (allows12)
        {
            _ = extensions
                .Add(ExtensionType.EcPointFormats, HelloExtensions.PointFormats())
                .Add(ExtensionType.ExtendedMasterSecret, [])
                .Add(ExtensionType.RenegotiationInfo, HelloExtensions.EmptyRenegotiationInfo());
        }

        if (!_settings.SrtpProfiles.IsEmpty)
        {
            _ = extensions.Add(
                ExtensionType.UseSrtp,
                HelloExtensions.UseSrtp(_settings.SrtpProfiles)
            );
        }

        if (!_settings.ApplicationProtocols.IsEmpty)
        {
            _ = extensions.Add(
                ExtensionType.ApplicationLayerProtocolNegotiation,
                HelloExtensions.ApplicationProtocols(_settings.ApplicationProtocols)
            );
        }

        if (allows13)
        {
            _keyShare13 ??= KeyShare.Create(KeyShare.SupportedGroups.First());
            _ = extensions
                .Add(
                    ExtensionType.SupportedVersions,
                    Messages13.SupportedVersions(
                        allows12
                            ? [ProtocolVersion.Dtls13, ProtocolVersion.Dtls12]
                            : [ProtocolVersion.Dtls13]
                    )
                )
                .Add(
                    ExtensionType.KeyShare,
                    Messages13.ClientKeyShares([(_keyShare13.Group, _keyShare13.PublicKey)])
                );
            if (_cookie13 is not null)
            {
                _ = extensions.Add(ExtensionType.Cookie, Messages13.Cookie(_cookie13));
            }
        }

        ClientHello hello = new(
            _localRandom,
            [],
            cookie,
            [
                .. (allows13 ? _settings.CipherSuites13 : []).Select(static s => (ushort)s.Suite),
                .. (allows12 ? _settings.CipherSuites : []).Select(static s => (ushort)s.Suite),
            ],
            extensions
        );
        HandshakeMessage message = NewMessage(HandshakeType.ClientHello, hello.Encode);
        _transcript.Add(message);
        if (allows13)
        {
            (_transcript13 ??= new Transcript()).Add13(message.Type, message.Body);
        }

        Flight flight = new();
        flight.AddMessage(0, message);
        SendFlight(flight, timed: true);
    }

    private void ClientReceive(HandshakeMessage message)
    {
        switch (_step, message.Type)
        {
            case (Step.ServerHello, HandshakeType.HelloVerifyRequest) when !_cookieReceived:
                // Only a DTLS 1.2 server sends a HelloVerifyRequest (RFC 9147 §5.2).
                RequireVersion(DtlsProtocols.Dtls12);
                ReceiveHelloVerifyRequest(message);
                return;
            case (Step.ServerHello, HandshakeType.ServerHello):
                ServerHello serverHello = ServerHello.Decode(message.Body);
                if (
                    serverHello.Extensions.TryGet(
                        ExtensionType.SupportedVersions,
                        out ReadOnlySpan<byte> selected
                    )
                )
                {
                    if (Messages13.ReadSelectedVersion(selected) != ProtocolVersion.Dtls13)
                    {
                        throw DtlsException.IllegalParameter(
                            "the server selected a version that was not offered"
                        );
                    }

                    RequireVersion(DtlsProtocols.Dtls13);
                    ReceiveServerHello13(message, serverHello);
                    return;
                }

                RequireVersion(DtlsProtocols.Dtls12);
                _version = DtlsProtocols.Dtls12;
                _transcript.Add(message);
                ReceiveServerHello(serverHello);
                _step = Step.ServerCertificate;
                return;
            case (Step.ServerCertificate, HandshakeType.Certificate):
                _transcript.Add(message);
                CertificateMessage certificate = CertificateMessage.Decode(message.Body);
                if (certificate.Chain.IsEmpty)
                {
                    throw DtlsException.HandshakeFailure("the server sent no certificate");
                }

                AcceptRemoteCertificate(certificate);
                _step = Step.ServerKeyExchange;
                return;
            case (Step.ServerKeyExchange, HandshakeType.ServerKeyExchange):
                _transcript.Add(message);
                ReceiveServerKeyExchange(ServerKeyExchange.Decode(message.Body));
                _step = Step.CertificateRequestOrDone;
                return;
            case (Step.CertificateRequestOrDone, HandshakeType.CertificateRequest):
                _transcript.Add(message);
                _certificateRequest = CertificateRequest.Decode(message.Body);
                _step = Step.ServerHelloDone;
                return;
            case (
                Step.CertificateRequestOrDone
                    or Step.ServerHelloDone,
                HandshakeType.ServerHelloDone
            ):
                _transcript.Add(message);
                if (message.Body.Length != 0)
                {
                    throw DtlsException.Decode("a ServerHelloDone with a body");
                }

                SendClientKeyExchangeFlight();
                _step = Step.Finished;
                return;
            case (Step.Finished, HandshakeType.Finished):
                ReceiveFinished(message, fromClient: false);
                Connected();
                return;
            default:
                throw DtlsException.Unexpected($"{message.Type} where the client expected {_step}");
        }
    }

    // The server asks the client to prove its address (RFC 6347 §4.2.1): the ClientHello is sent again
    // with the cookie, and neither it nor the HelloVerifyRequest counts in the transcript.
    private void ReceiveHelloVerifyRequest(HandshakeMessage message)
    {
        HelloVerifyRequest request = HelloVerifyRequest.Decode(message.Body);
        _cookieReceived = true;
        _transcript.Clear();
        LogCookieReceived(request.Cookie.Length);
        SendClientHello(request.Cookie);
    }

    private void ReceiveServerHello(ServerHello hello)
    {
        if (hello.Version != ProtocolVersion.Dtls12)
        {
            throw new DtlsException(
                DtlsAlert.ProtocolVersion,
                isRemote: false,
                $"The server chose version 0x{hello.Version:X4}; Dtls.NET speaks DTLS 1.2."
            );
        }

        // A server that speaks DTLS 1.3 marks a DTLS 1.2 ServerHello (RFC 8446 §4.1.3): seeing the mark
        // after offering 1.3 means an attacker removed the offer.
        if (
            _settings.Allows13
            && hello.Random.AsSpan(24).SequenceEqual(Messages13.DowngradeSentinel)
        )
        {
            throw DtlsException.IllegalParameter("the server marked a downgrade from DTLS 1.3");
        }

        _peerRandom = hello.Random;
        _suite = _settings.CipherSuites.FirstOrDefault(s => (ushort)s.Suite == hello.CipherSuite);
        if (_suite.Suite == default)
        {
            throw DtlsException.IllegalParameter(
                $"the server chose cipher suite 0x{hello.CipherSuite:X4}, which was not offered"
            );
        }

        foreach (ushort type in hello.Extensions.Types)
        {
            if (
                type
                    is not (
                        ExtensionType.EcPointFormats
                        or ExtensionType.ExtendedMasterSecret
                        or ExtensionType.RenegotiationInfo
                        or ExtensionType.UseSrtp
                        or ExtensionType.ApplicationLayerProtocolNegotiation
                    )
                || (type == ExtensionType.UseSrtp && _settings.SrtpProfiles.IsEmpty)
                || (
                    type == ExtensionType.ApplicationLayerProtocolNegotiation
                    && _settings.ApplicationProtocols.IsEmpty
                )
            )
            {
                throw new DtlsException(
                    DtlsAlert.UnsupportedExtension,
                    isRemote: false,
                    $"The server answered with extension {type}, which was not offered."
                );
            }
        }

        _extendedMasterSecret = hello.Extensions.Contains(ExtensionType.ExtendedMasterSecret);
        if (!_extendedMasterSecret && _settings.RequireExtendedMasterSecret)
        {
            throw DtlsException.HandshakeFailure(
                "the server does not use the extended master secret"
            );
        }

        if (
            hello.Extensions.TryGet(
                ExtensionType.RenegotiationInfo,
                out ReadOnlySpan<byte> renegotiation
            ) && !HelloExtensions.IsEmptyRenegotiationInfo(renegotiation)
        )
        {
            throw DtlsException.HandshakeFailure("the server's renegotiation_info is not empty");
        }

        if (
            hello.Extensions.TryGet(ExtensionType.EcPointFormats, out ReadOnlySpan<byte> formats)
            && !HelloExtensions.OffersUncompressedPoints(formats)
        )
        {
            throw DtlsException.IllegalParameter("the server does not accept uncompressed points");
        }

        if (!_settings.SrtpProfiles.IsEmpty)
        {
            if (!hello.Extensions.TryGet(ExtensionType.UseSrtp, out ReadOnlySpan<byte> srtp))
            {
                throw DtlsException.HandshakeFailure("the server does not use DTLS-SRTP");
            }

            List<SrtpProtectionProfile> chosen = HelloExtensions.ReadUseSrtp(srtp);
            if (chosen.Count != 1 || !_settings.SrtpProfiles.Contains(chosen[0]))
            {
                throw DtlsException.IllegalParameter(
                    "the server chose an SRTP protection profile that was not offered"
                );
            }

            _srtpProfile = chosen[0];
        }

        if (
            hello.Extensions.TryGet(
                ExtensionType.ApplicationLayerProtocolNegotiation,
                out ReadOnlySpan<byte> alpn
            )
        )
        {
            List<SslApplicationProtocol> chosen = HelloExtensions.ReadApplicationProtocols(alpn);
            if (chosen.Count != 1 || !_settings.ApplicationProtocols.Contains(chosen[0]))
            {
                throw DtlsException.IllegalParameter(
                    "the server chose an application protocol that was not offered"
                );
            }

            NegotiatedApplicationProtocol = chosen[0];
        }
    }

    private void ReceiveServerKeyExchange(ServerKeyExchange exchange)
    {
        if (!KeyShare.IsSupported(exchange.Group))
        {
            throw DtlsException.IllegalParameter(
                $"the server chose the group {exchange.Group}, which was not offered"
            );
        }

        if (!Signatures.Authenticates(exchange.Scheme, _suite.Authentication))
        {
            throw DtlsException.IllegalParameter(
                $"the server signed with {exchange.Scheme}, which does not suit the cipher suite"
            );
        }

        (byte[] client, byte[] server) = Randoms;
        byte[] parameters = exchange.SignedParameters();
        byte[] signed = [.. client, .. server, .. parameters];
        if (!Signatures.Verify(_remoteCertificate!, exchange.Scheme, signed, exchange.Signature))
        {
            throw DtlsException.DecryptError("the server's key exchange signature");
        }

        _keyShare = KeyShare.Create(exchange.Group);
        _premasterSecret = _keyShare.DeriveSecret(exchange.PublicKey);
    }

    // Flight 5: the client's certificate when asked for, its key share, the proof it holds the
    // certificate's key, and its Finished under the new keys.
    private void SendClientKeyExchangeFlight()
    {
        Flight flight = new();
        LocalCredential? credential = null;
        if (_certificateRequest is not null)
        {
            credential = _settings.Credential;
            if (
                credential is not null
                && !Signatures.CanSignAny(credential, _certificateRequest.SignatureSchemes)
            )
            {
                // A certificate the server cannot verify is not sent; the server decides whether to go on
                // without one.
                LogClientCertificateUnusable();
                credential = null;
            }

            ImmutableArray<byte[]> chain = credential?.Chain ?? [];
            HandshakeMessage certificate = NewMessage(
                HandshakeType.Certificate,
                new CertificateMessage(chain).Encode
            );
            _transcript.Add(certificate);
            flight.AddMessage(0, certificate);
        }

        HandshakeMessage keyExchange = NewMessage(
            HandshakeType.ClientKeyExchange,
            new ClientKeyExchange(_keyShare!.PublicKey).Encode
        );
        _transcript.Add(keyExchange);
        flight.AddMessage(0, keyExchange);
        DeriveKeys();

        if (credential is not null)
        {
            SignatureScheme scheme = Signatures.Choose(
                credential,
                _certificateRequest!.SignatureSchemes
            );
            byte[] signature = Signatures.Sign(credential, scheme, _transcript.Bytes);
            HandshakeMessage verify = NewMessage(
                HandshakeType.CertificateVerify,
                new CertificateVerify(scheme, signature).Encode
            );
            _transcript.Add(verify);
            flight.AddMessage(0, verify);
        }

        flight.AddChangeCipherSpec(0);
        flight.AddMessage(1, FinishedMessage(fromClient: true));
        SendFlight(flight, timed: true);
    }
}
