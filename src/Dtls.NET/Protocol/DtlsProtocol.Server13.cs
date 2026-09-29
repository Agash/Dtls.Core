using System.Buffers.Binary;
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
    // The cookie a HelloRetryRequest carries: a format byte, the first ClientHello's hash, the suite
    // and the group asked for, then an HMAC over all of it, the client's random and its session id.
    // The server keeps nothing between the two ClientHellos (RFC 9147 §5.1): the second brings back
    // what the transcript needs.
    private const byte CookieFormat = 1;
    private const int CookieMacLength = 32;

    private bool Offers13(ClientHello hello) =>
        _settings.Allows13
        && hello.Extensions.TryGet(ExtensionType.SupportedVersions, out ReadOnlySpan<byte> versions)
        && Messages13.OffersVersion(versions, ProtocolVersion.Dtls13);

    private void ServerReceive13(HandshakeMessage message)
    {
        switch (_step, message.Type)
        {
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
        CipherSuiteInfo suite = _settings.CipherSuites13.FirstOrDefault(s =>
            hello.CipherSuites.Contains((ushort)s.Suite)
        );
        if (suite.Suite == default)
        {
            throw DtlsException.HandshakeFailure(
                "the client offers no DTLS 1.3 cipher suite this server uses"
            );
        }

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
        _suite = suite;

        if (extensions.TryGet(ExtensionType.Cookie, out ReadOnlySpan<byte> cookieData))
        {
            // The second ClientHello: it must answer the HelloRetryRequest that carried its cookie.
            byte[] cookie = Messages13.ReadCookie(cookieData);
            if (
                !TryOpenCookie(cookie, hello, out byte[] firstHash, out NamedGroup requested)
                || (requested != default && shareGroup != requested)
                || shareKey is null
            )
            {
                // RFC 9147 §5.1. The server keeps no state for the client, so it answers and forgets.
                LogCookieRefused();
                SendAlert(DtlsAlert.IllegalParameter, fatal: true);
                _reassembler.Restart(checked((ushort)(message.MessageSeq + 1)));
                return;
            }

            _transcript13 = new Transcript();
            _transcript13.Add13(HandshakeType.MessageHash, firstHash);
            _transcript13.Add13(
                HandshakeType.ServerHello,
                HelloRetryRequestBody(hello.SessionId, requested, cookie)
            );
            _transcript13.Add13(message.Type, message.Body);

            // The HelloRetryRequest was this server's message 0; the ServerHello is 1.
            _sendSequence = 1;
        }
        else if (_settings.CookieExchange || shareKey is null)
        {
            NamedGroup group = shareKey is null
                ? KeyShare.SupportedGroups.FirstOrDefault(groups.Contains)
                : default;
            if (shareKey is null && group == default)
            {
                throw DtlsException.HandshakeFailure(
                    "the client offers no elliptic curve group this server uses"
                );
            }

            SendHelloRetryRequest(message, hello, group);
            return;
        }
        else
        {
            _transcript13 = new Transcript();
            _transcript13.Add13(message.Type, message.Body);
        }

        _peerSignatureSchemes = HelloExtensions.ReadSignatureAlgorithms(schemes);
        SelectSrtpAndApplicationProtocol(extensions);
        _peerRandom = hello.Random;
        SendServerFlight13(hello, shareGroup, shareKey);
        _step = _settings.ClientCertificateRequired ? Step.ClientCertificate : Step.Finished;
    }

    // Asks for the ClientHello again with a cookie and, when needed, a key share for a group this
    // server uses, then forgets the client: like a HelloVerifyRequest, it is answered again whenever
    // the first ClientHello is sent again.
    private void SendHelloRetryRequest(
        HandshakeMessage message,
        ClientHello hello,
        NamedGroup group
    )
    {
        Span<byte> firstHash = stackalloc byte[Prf.HashSize(_suite.PrfHash)];
        using (Transcript first = new())
        {
            first.Add13(message.Type, message.Body);
            _ = KeySchedule13.Hash(_suite.PrfHash, first.Bytes, firstHash);
        }

        byte[] cookie = SealCookie(firstHash, group, hello);
        HandshakeMessage request = new(
            HandshakeType.ServerHello,
            message.MessageSeq,
            HelloRetryRequestBody(hello.SessionId, group, cookie)
        );
        _reassembler.Restart(checked((ushort)(message.MessageSeq + 1)));
        Flight flight = new();
        flight.AddMessage(0, request);
        Transmit(flight);
        LogCookieSent();
    }

    // The HelloRetryRequest for the suite, a group and a cookie; built the same way when it is sent
    // and when the transcript is rebuilt from the cookie.
    private byte[] HelloRetryRequestBody(byte[] sessionId, NamedGroup group, byte[] cookie)
    {
        Extensions extensions = new Extensions().Add(
            ExtensionType.SupportedVersions,
            Messages13.SelectedVersion(ProtocolVersion.Dtls13)
        );
        if (group != default)
        {
            _ = extensions.Add(ExtensionType.KeyShare, Messages13.SelectedGroup(group));
        }

        _ = extensions.Add(ExtensionType.Cookie, Messages13.Cookie(cookie));
        _scratch.Clear();
        new ServerHello(
            Messages13.HelloRetryRequestRandom.ToArray(),
            sessionId,
            (ushort)_suite.Suite,
            extensions
        ).Encode(_scratch);
        return _scratch.ToArray();
    }

    private byte[] SealCookie(ReadOnlySpan<byte> firstHash, NamedGroup group, ClientHello hello)
    {
        _cookieSecret ??= RandomNumberGenerator.GetBytes(32);
        int bodyLength = 2 + firstHash.Length + 4;
        byte[] cookie = new byte[bodyLength + CookieMacLength];
        cookie[0] = CookieFormat;
        cookie[1] = (byte)firstHash.Length;
        firstHash.CopyTo(cookie.AsSpan(2));
        BinaryPrimitives.WriteUInt16BigEndian(
            cookie.AsSpan(2 + firstHash.Length),
            (ushort)_suite.Suite
        );
        BinaryPrimitives.WriteUInt16BigEndian(cookie.AsSpan(4 + firstHash.Length), (ushort)group);
        CookieMac(cookie.AsSpan(0, bodyLength), hello, cookie.AsSpan(bodyLength));
        return cookie;
    }

    private bool TryOpenCookie(
        byte[] cookie,
        ClientHello hello,
        out byte[] firstHash,
        out NamedGroup group
    )
    {
        firstHash = [];
        group = default;
        int hashLength = Prf.HashSize(_suite.PrfHash);
        int bodyLength = 2 + hashLength + 4;
        if (
            _cookieSecret is null
            || cookie.Length != bodyLength + CookieMacLength
            || cookie[0] != CookieFormat
            || cookie[1] != hashLength
        )
        {
            return false;
        }

        Span<byte> mac = stackalloc byte[CookieMacLength];
        CookieMac(cookie.AsSpan(0, bodyLength), hello, mac);
        ushort suite = BinaryPrimitives.ReadUInt16BigEndian(cookie.AsSpan(2 + hashLength));
        if (
            !CryptographicOperations.FixedTimeEquals(mac, cookie.AsSpan(bodyLength))
            || suite != (ushort)_suite.Suite
        )
        {
            return false;
        }

        firstHash = cookie.AsSpan(2, hashLength).ToArray();
        group = (NamedGroup)BinaryPrimitives.ReadUInt16BigEndian(cookie.AsSpan(4 + hashLength));
        return true;
    }

    // The second ClientHello keeps the first one's random and session id (RFC 8446 §4.1.2), so the MAC
    // ties the cookie to that client.
    private void CookieMac(ReadOnlySpan<byte> body, ClientHello hello, Span<byte> destination)
    {
        using IncrementalHash hmac = IncrementalHash.CreateHMAC(
            HashAlgorithmName.SHA256,
            _cookieSecret!
        );
        hmac.AppendData(body);
        hmac.AppendData(hello.Random);
        hmac.AppendData(hello.SessionId);
        _ = hmac.GetHashAndReset(destination);
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
