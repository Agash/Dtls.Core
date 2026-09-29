using System.Security.Cryptography;
using Dtls.NET.Crypto;
using Dtls.NET.Handshake;
using Dtls.NET.Records;

namespace Dtls.NET.Protocol;

// The server's side of the DTLS 1.3 handshake (RFC 9147 §5.7): a HelloRetryRequest when the client
// must prove its address or send another key share, then ServerHello, EncryptedExtensions,
// CertificateRequest, Certificate, CertificateVerify and Finished; the client's flight is acknowledged.
internal sealed partial class DtlsProtocol
{
    private byte[]? _expectedCookie;

    private bool Offers13(ClientHello hello) =>
        _settings.Allows13
        && hello.Extensions.TryGet(ExtensionType.SupportedVersions, out ReadOnlySpan<byte> versions)
        && Messages13.OffersVersion(versions, ProtocolVersion.Dtls13);

    private void ServerReceive13(HandshakeMessage message)
    {
        switch (_step, message.Type)
        {
            case (Step.SecondClientHello, HandshakeType.ClientHello):
                ReceiveClientHello13(message, ClientHello.Decode(message.Body));
                return;
            case (Step.ClientCertificate, HandshakeType.Certificate):
                Certificate13 certificate = Certificate13.Decode(message.Body);
                if (certificate.Context.Length != 0)
                {
                    throw DtlsException.IllegalParameter(
                        "the client's certificate answers another request"
                    );
                }

                if (certificate.Chain.IsEmpty)
                {
                    throw new DtlsException(
                        DtlsAlert.CertificateRequired,
                        isRemote: false,
                        "The client sent no certificate, and one is required."
                    );
                }

                AcceptRemoteCertificate(certificate);
                _transcript13!.Add13(message.Type, message.Body);
                _step = Step.CertificateVerify;
                return;
            case (Step.CertificateVerify, HandshakeType.CertificateVerify):
                ReceiveCertificateVerify13(message, fromServer: false);
                _step = Step.Finished;
                return;
            case (Step.Finished, HandshakeType.Finished):
                ReceiveFinished13(message, fromClient: true);
                _flightTimed = false;
                Connected();
                return;
            default:
                throw DtlsException.Unexpected($"{message.Type} where the server expected {_step}");
        }
    }

    private void ReceiveClientHello13(HandshakeMessage message, ClientHello hello)
    {
        bool second = _step == Step.SecondClientHello;
        CipherSuiteInfo suite = _settings.CipherSuites13.FirstOrDefault(s =>
            hello.CipherSuites.Contains((ushort)s.Suite)
        );
        if (suite.Suite == default || (second && suite.Suite != _suite.Suite))
        {
            throw DtlsException.HandshakeFailure(
                "the client offers no DTLS 1.3 cipher suite this server uses"
            );
        }

        _suite = suite;
        Extensions extensions = hello.Extensions;
        if (
            !extensions.TryGet(ExtensionType.SignatureAlgorithms, out ReadOnlySpan<byte> schemes)
            || !extensions.TryGet(ExtensionType.SupportedGroups, out ReadOnlySpan<byte> groupData)
            || !extensions.TryGet(ExtensionType.KeyShare, out ReadOnlySpan<byte> shareData)
        )
        {
            throw new DtlsException(
                DtlsAlert.MissingExtension,
                isRemote: false,
                "A DTLS 1.3 ClientHello needs signature_algorithms, supported_groups and key_share."
            );
        }

        List<(NamedGroup Group, byte[] Key)> shares = Messages13.ReadClientKeyShares(shareData);
        List<NamedGroup> groups = HelloExtensions.ReadSupportedGroups(groupData);
        (NamedGroup shareGroup, byte[]? shareKey) = shares.Find(s => KeyShare.IsSupported(s.Group));
        NamedGroup? retryGroup = null;
        if (shareKey is null)
        {
            retryGroup = KeyShare.SupportedGroups.FirstOrDefault(groups.Contains);
            if (retryGroup == default(NamedGroup))
            {
                throw DtlsException.HandshakeFailure(
                    "the client offers no elliptic curve group this server uses"
                );
            }
        }

        bool cookieValid =
            !_settings.CookieExchange
            || (
                _expectedCookie is not null
                && extensions.TryGet(ExtensionType.Cookie, out ReadOnlySpan<byte> cookie)
                && CryptographicOperations.FixedTimeEquals(
                    Messages13.ReadCookie(cookie),
                    _expectedCookie
                )
            );
        if (second && (!cookieValid || shareKey is null))
        {
            // RFC 9147 §5.1: a ClientHello with an invalid cookie ends the handshake.
            throw DtlsException.IllegalParameter(
                "the second ClientHello does not answer the HelloRetryRequest"
            );
        }

        _transcript13 ??= new Transcript();
        _transcript13.Add13(message.Type, message.Body);
        if (!cookieValid || shareKey is null)
        {
            SendHelloRetryRequest(hello, retryGroup);
            return;
        }

        _peerSignatureSchemes = HelloExtensions.ReadSignatureAlgorithms(schemes);
        SelectSrtpAndApplicationProtocol(extensions);
        _peerRandom = hello.Random;
        SendServerFlight13(hello, shareGroup, shareKey);
        _step = _settings.ClientCertificateRequired ? Step.ClientCertificate : Step.Finished;
    }

    // Asks for the ClientHello again, with a cookie that proves the client's address and, when needed,
    // a key share for a group this server uses (RFC 9147 §5.1). The transcript keeps the first
    // ClientHello as its hash.
    private void SendHelloRetryRequest(ClientHello hello, NamedGroup? group)
    {
        Extensions extensions = new Extensions().Add(
            ExtensionType.SupportedVersions,
            Messages13.SelectedVersion(ProtocolVersion.Dtls13)
        );
        if (group is { } selected)
        {
            _ = extensions.Add(ExtensionType.KeyShare, Messages13.SelectedGroup(selected));
        }

        if (_settings.CookieExchange)
        {
            _expectedCookie = RandomNumberGenerator.GetBytes(32);
            _ = extensions.Add(ExtensionType.Cookie, Messages13.Cookie(_expectedCookie));
        }

        _transcript13!.ReplaceWithMessageHash(_suite.PrfHash);
        ServerHello request = new(
            Messages13.HelloRetryRequestRandom.ToArray(),
            hello.SessionId,
            (ushort)_suite.Suite,
            extensions
        );
        HandshakeMessage message = NewMessage(HandshakeType.ServerHello, request.Encode);
        _transcript13.Add13(message.Type, message.Body);
        Flight flight = new();
        flight.AddMessage(0, message);

        // Not timed: the client sends its ClientHello again when this is lost, and gets it again.
        SendFlight(flight, timed: false);
        _step = Step.SecondClientHello;
        LogCookieSent();
    }

    // ServerHello in epoch 0, the rest in epoch 2. Sent until the client's flight arrives.
    private void SendServerFlight13(ClientHello hello, NamedGroup group, byte[] clientKey)
    {
        LocalCredential credential = _settings.Credential!;
        SignatureScheme scheme = Signatures.Choose13(credential, _peerSignatureSchemes);
        _keyShare13 = KeyShare.Create(group);
        byte[] shared = _keyShare13.DeriveSecret(clientKey);
        Extensions extensions = new Extensions()
            .Add(
                ExtensionType.SupportedVersions,
                Messages13.SelectedVersion(ProtocolVersion.Dtls13)
            )
            .Add(ExtensionType.KeyShare, Messages13.ServerKeyShare(group, _keyShare13.PublicKey));
        HandshakeMessage serverHello = NewMessage(
            HandshakeType.ServerHello,
            new ServerHello(_localRandom, hello.SessionId, (ushort)_suite.Suite, extensions).Encode
        );
        _transcript13!.Add13(serverHello.Type, serverHello.Body);
        DeriveHandshakeSecrets(shared);
        CryptographicOperations.ZeroMemory(shared);

        Flight flight = new();
        flight.AddMessage(0, serverHello);
        AddEncrypted(
            flight,
            NewMessage(
                HandshakeType.EncryptedExtensions,
                new EncryptedExtensions(NegotiatedExtensions()).Encode
            )
        );
        if (_settings.ClientCertificateRequired)
        {
            Extensions requested = new Extensions().Add(
                ExtensionType.SignatureAlgorithms,
                HelloExtensions.SignatureAlgorithms(Signatures.Accepted13)
            );
            AddEncrypted(
                flight,
                NewMessage(
                    HandshakeType.CertificateRequest,
                    new CertificateRequest13([], requested).Encode
                )
            );
        }

        AddEncrypted(
            flight,
            NewMessage(HandshakeType.Certificate, new Certificate13([], credential.Chain).Encode)
        );
        flight.AddMessage(HandshakeEpoch, CertificateVerifyMessage13(credential, scheme));
        flight.AddMessage(HandshakeEpoch, FinishedMessage13(fromClient: false));
        DeriveApplicationSecrets();
        InstallApplicationWriteKeys();
        SendFlight(flight, timed: true);
    }

    private void AddEncrypted(Flight flight, HandshakeMessage message)
    {
        _transcript13!.Add13(message.Type, message.Body);
        flight.AddMessage(HandshakeEpoch, message);
    }
}
