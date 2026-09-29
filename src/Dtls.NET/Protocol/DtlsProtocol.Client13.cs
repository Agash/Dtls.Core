using System.Collections.Immutable;
using System.Net.Security;
using Dtls.NET.Crypto;
using Dtls.NET.Handshake;
using Dtls.NET.Records;

namespace Dtls.NET.Protocol;

// The client's side of the DTLS 1.3 handshake (RFC 9147 §5.7): ClientHello, perhaps again after a
// HelloRetryRequest, then the server's flight, then the client's Certificate, CertificateVerify and
// Finished, sent until the server acknowledges them.
internal sealed partial class DtlsProtocol
{
    private bool _retried;
    private byte[]? _cookie13;
    private CertificateRequest13? _certificateRequest13;

    private void RequireVersion(DtlsProtocols version)
    {
        if ((_settings.Protocols & version) == 0)
        {
            throw new DtlsException(
                DtlsAlert.ProtocolVersion,
                isRemote: false,
                $"The peer chose {version}, which this side does not allow."
            );
        }
    }

    private void ReceiveServerHello13(HandshakeMessage message, ServerHello hello)
    {
        CipherSuiteInfo suite = _settings.CipherSuites13.FirstOrDefault(s =>
            (ushort)s.Suite == hello.CipherSuite
        );
        if (suite.Suite == default)
        {
            throw DtlsException.IllegalParameter(
                $"the server chose cipher suite 0x{hello.CipherSuite:X4}, which was not offered"
            );
        }

        if (hello.Version != ProtocolVersion.Dtls12 || hello.SessionId.Length != 0)
        {
            throw DtlsException.IllegalParameter("the ServerHello's legacy fields");
        }

        foreach (ushort type in hello.Extensions.Types)
        {
            if (
                type
                is not (
                    ExtensionType.SupportedVersions
                    or ExtensionType.KeyShare
                    or ExtensionType.Cookie
                )
            )
            {
                throw new DtlsException(
                    DtlsAlert.UnsupportedExtension,
                    isRemote: false,
                    $"The server answered with extension {type}, which a ServerHello does not carry."
                );
            }
        }

        _version = DtlsProtocols.Dtls13;
        _suite = suite;
        if (hello.Random.AsSpan().SequenceEqual(Messages13.HelloRetryRequestRandom))
        {
            ReceiveHelloRetryRequest(message, hello);
            return;
        }

        if (!hello.Extensions.TryGet(ExtensionType.KeyShare, out ReadOnlySpan<byte> share))
        {
            throw new DtlsException(
                DtlsAlert.MissingExtension,
                isRemote: false,
                "The ServerHello has no key share."
            );
        }

        (NamedGroup group, byte[] key) = Messages13.ReadServerKeyShare(share);
        if (group != _keyShare13!.Group)
        {
            throw DtlsException.IllegalParameter(
                "the server's key share is not for the group offered"
            );
        }

        _peerRandom = hello.Random;
        _transcript13!.Add13(message.Type, message.Body);
        byte[] shared = _keyShare13.DeriveSecret(key);
        DeriveHandshakeSecrets(shared);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(shared);
        _step = Step.EncryptedExtensions;
    }

    // The server wants a different key share, a cookie, or both (RFC 8446 §4.1.4, RFC 9147 §5.1): the
    // ClientHello is sent again with them, and the transcript keeps the first one as its hash.
    private void ReceiveHelloRetryRequest(HandshakeMessage message, ServerHello request)
    {
        if (_retried)
        {
            throw DtlsException.Unexpected("a second HelloRetryRequest");
        }

        _retried = true;
        bool changed = false;
        if (request.Extensions.TryGet(ExtensionType.KeyShare, out ReadOnlySpan<byte> selected))
        {
            NamedGroup group = Messages13.ReadSelectedGroup(selected);
            if (!KeyShare.IsSupported(group) || group == _keyShare13!.Group)
            {
                throw DtlsException.IllegalParameter(
                    $"the HelloRetryRequest asks for the group {group}"
                );
            }

            _keyShare13.Dispose();
            _keyShare13 = KeyShare.Create(group);
            changed = true;
        }

        if (request.Extensions.TryGet(ExtensionType.Cookie, out ReadOnlySpan<byte> cookie))
        {
            _cookie13 = Messages13.ReadCookie(cookie);
            changed = true;
        }

        if (!changed)
        {
            throw DtlsException.IllegalParameter("a HelloRetryRequest that changes nothing");
        }

        _transcript13!.ReplaceWithMessageHash(_suite.PrfHash);
        _transcript13.Add13(message.Type, message.Body);
        LogRetryRequested();
        SendClientHello(cookie: []);
    }

    private void ClientReceive13(HandshakeMessage message)
    {
        switch (_step, message.Type)
        {
            case (Step.ServerHello, HandshakeType.ServerHello):
                // After a HelloRetryRequest: the ServerHello must still select DTLS 1.3.
                ServerHello hello = ServerHello.Decode(message.Body);
                if (
                    !hello.Extensions.TryGet(
                        ExtensionType.SupportedVersions,
                        out ReadOnlySpan<byte> selected
                    )
                    || Messages13.ReadSelectedVersion(selected) != ProtocolVersion.Dtls13
                    || hello.CipherSuite != (ushort)_suite.Suite
                )
                {
                    throw DtlsException.IllegalParameter(
                        "the ServerHello does not follow its HelloRetryRequest"
                    );
                }

                ReceiveServerHello13(message, hello);
                return;
            case (Step.EncryptedExtensions, HandshakeType.EncryptedExtensions):
                ReceiveEncryptedExtensions(EncryptedExtensions.Decode(message.Body));
                _transcript13!.Add13(message.Type, message.Body);
                _step = Step.CertificateRequestOrCertificate;
                return;
            case (Step.CertificateRequestOrCertificate, HandshakeType.CertificateRequest)
                when _certificateRequest13 is null:
                _certificateRequest13 = CertificateRequest13.Decode(message.Body);
                if (!_certificateRequest13.Extensions.Contains(ExtensionType.SignatureAlgorithms))
                {
                    throw new DtlsException(
                        DtlsAlert.MissingExtension,
                        isRemote: false,
                        "The CertificateRequest has no signature_algorithms."
                    );
                }

                _transcript13!.Add13(message.Type, message.Body);
                return;
            case (Step.CertificateRequestOrCertificate, HandshakeType.Certificate):
                Certificate13 certificate = Certificate13.Decode(message.Body);
                if (certificate.Chain.IsEmpty || certificate.Context.Length != 0)
                {
                    throw DtlsException.HandshakeFailure("the server sent no certificate");
                }

                AcceptRemoteCertificate(certificate);
                _transcript13!.Add13(message.Type, message.Body);
                _step = Step.ServerCertificateVerify;
                return;
            case (Step.ServerCertificateVerify, HandshakeType.CertificateVerify):
                ReceiveCertificateVerify13(message, fromServer: true);
                _step = Step.Finished;
                return;
            case (Step.Finished, HandshakeType.Finished):
                ReceiveFinished13(message, fromClient: false);
                DeriveApplicationSecrets();
                SendClientFinishedFlight13();
                InstallApplicationWriteKeys();
                Connected();
                return;
            default:
                throw DtlsException.Unexpected($"{message.Type} where the client expected {_step}");
        }
    }

    // What the server agreed to that is not about keys: DTLS-SRTP and ALPN, with the same rules as
    // in DTLS 1.2.
    private void ReceiveEncryptedExtensions(EncryptedExtensions encrypted)
    {
        foreach (ushort type in encrypted.Extensions.Types)
        {
            if (
                (type == ExtensionType.UseSrtp && _settings.SrtpProfiles.IsEmpty)
                || (
                    type == ExtensionType.ApplicationLayerProtocolNegotiation
                    && _settings.ApplicationProtocols.IsEmpty
                )
                || type
                    is ExtensionType.SupportedVersions
                        or ExtensionType.KeyShare
                        or ExtensionType.Cookie
                        or ExtensionType.ExtendedMasterSecret
                        or ExtensionType.RenegotiationInfo
                        or ExtensionType.EcPointFormats
            )
            {
                throw new DtlsException(
                    DtlsAlert.UnsupportedExtension,
                    isRemote: false,
                    $"The server's EncryptedExtensions carry extension {type}, which it may not."
                );
            }
        }

        if (!_settings.SrtpProfiles.IsEmpty)
        {
            if (!encrypted.Extensions.TryGet(ExtensionType.UseSrtp, out ReadOnlySpan<byte> srtp))
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
            encrypted.Extensions.TryGet(
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

    // The client's last flight, in epoch 2: its certificate when asked for, the proof it holds the key,
    // and its Finished. It is sent until the server acknowledges it (RFC 9147 §5.8.1).
    private void SendClientFinishedFlight13()
    {
        Flight flight = new();
        if (_certificateRequest13 is { } request)
        {
            ImmutableArray<SignatureScheme> schemes = request.Extensions.TryGet(
                ExtensionType.SignatureAlgorithms,
                out ReadOnlySpan<byte> data
            )
                ? [.. HelloExtensions.ReadSignatureAlgorithms(data)]
                : [];
            LocalCredential? credential = _settings.Credential;
            if (credential is not null && !schemes.Any(s => Signatures.CanSign13(credential, s)))
            {
                LogClientCertificateUnusable();
                credential = null;
            }

            HandshakeMessage certificate = NewMessage(
                HandshakeType.Certificate,
                new Certificate13(request.Context, credential?.Chain ?? []).Encode
            );
            _transcript13!.Add13(certificate.Type, certificate.Body);
            flight.AddMessage(HandshakeEpoch, certificate);
            if (credential is not null)
            {
                flight.AddMessage(
                    HandshakeEpoch,
                    CertificateVerifyMessage13(credential, Signatures.Choose13(credential, schemes))
                );
            }
        }

        flight.AddMessage(HandshakeEpoch, FinishedMessage13(fromClient: true));
        SendFlight(flight, timed: true);
    }
}
