namespace Dtls.NET.Handshake;

// Handshake message types (RFC 5246 §7.4, RFC 6347 §4.2.2, RFC 8446 §4).
internal enum HandshakeType : byte
{
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    NewSessionTicket = 4,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    KeyUpdate = 24,

    // The stand-in for a ClientHello in the transcript after a HelloRetryRequest (RFC 8446 §4.4.1).
    MessageHash = 254,
}

// Extension types Dtls.NET sends or reads.
internal static class ExtensionType
{
    public const ushort SupportedGroups = 10;
    public const ushort EcPointFormats = 11;
    public const ushort SignatureAlgorithms = 13;
    public const ushort UseSrtp = 14;
    public const ushort ExtendedMasterSecret = 23;
    public const ushort SupportedVersions = 43;
    public const ushort Cookie = 44;
    public const ushort KeyShare = 51;
    public const ushort ApplicationLayerProtocolNegotiation = 16;
    public const ushort RenegotiationInfo = 0xFF01;
}

// Named groups for ECDHE (RFC 8422 §5.1.1, RFC 7748).
internal enum NamedGroup : ushort
{
    Secp256r1 = 23,
    Secp384r1 = 24,
    X25519 = 29,
}

// Signature schemes (RFC 8446 §4.2.3); in TLS 1.2 their two bytes are the hash and signature
// algorithm pairs of RFC 5246 §7.4.1.4.1.
internal enum SignatureScheme : ushort
{
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
}

// Client certificate types a CertificateRequest names (RFC 5246 §7.4.4, RFC 8422 §5.5).
internal static class ClientCertificateType
{
    public const byte RsaSign = 1;
    public const byte EcdsaSign = 64;
}
