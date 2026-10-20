using System.Security.Cryptography;
using Dtls.Core.Handshake;

namespace Dtls.Core.Crypto;

// An ephemeral ECDHE key pair on a named group. X25519 (RFC 7748) puts its 32-byte public key on the
// wire as it is and its 32-byte shared secret is the premaster secret (RFC 8422 section 5.11, RFC 8446
// section 7.4.2). The NIST curves put an uncompressed point (0x04 || X || Y, RFC 8422 section 5.4.1) and
// take the shared point's x coordinate (RFC 8422 section 5.10).
internal sealed class KeyShare : IDisposable
{
    private readonly ECDiffieHellman? _key;
    private readonly X25519DiffieHellman? _x25519;
    private readonly ECCurve _curve;
    private readonly int _coordinateSize;

    private KeyShare(NamedGroup group, ECCurve curve, int coordinateSize)
    {
        Group = group;
        _curve = curve;
        _coordinateSize = coordinateSize;
        _key = ECDiffieHellman.Create(curve);
        ECParameters parameters = _key.ExportParameters(false);
        PublicKey = new byte[1 + (2 * coordinateSize)];
        PublicKey[0] = 0x04;
        parameters.Q.X!.CopyTo(PublicKey.AsSpan(1 + coordinateSize - parameters.Q.X!.Length));
        parameters.Q.Y!.CopyTo(PublicKey.AsSpan(1 + (2 * coordinateSize) - parameters.Q.Y!.Length));
    }

    private KeyShare()
    {
        Group = NamedGroup.X25519;
        _x25519 = X25519DiffieHellman.GenerateKey();
        PublicKey = _x25519.ExportPublicKey();
    }

    public NamedGroup Group { get; }

    public byte[] PublicKey { get; }

    // The groups this platform can run, most preferred first: X25519 where the platform has it, as RFC
    // 9325 section 4.2.1 and RFC 8446 section 9.1 prefer, then the NIST curves.
    public static IEnumerable<NamedGroup> SupportedGroups
    {
        get
        {
            if (X25519DiffieHellman.IsSupported)
            {
                yield return NamedGroup.X25519;
            }

            yield return NamedGroup.Secp256r1;
            yield return NamedGroup.Secp384r1;
        }
    }

    public static bool IsSupported(NamedGroup group) =>
        group is NamedGroup.Secp256r1 or NamedGroup.Secp384r1
        || (group == NamedGroup.X25519 && X25519DiffieHellman.IsSupported);

    public static KeyShare Create(NamedGroup group) =>
        group switch
        {
            NamedGroup.X25519 when X25519DiffieHellman.IsSupported => new KeyShare(),
            NamedGroup.Secp256r1 => new KeyShare(group, ECCurve.NamedCurves.nistP256, 32),
            NamedGroup.Secp384r1 => new KeyShare(group, ECCurve.NamedCurves.nistP384, 48),
            _ => throw DtlsException.IllegalParameter($"the group {group} is not supported"),
        };

    // The premaster secret with a peer's public key. The point is decoded strictly and validated by
    // the platform on import, so an invalid or off-curve point fails here (RFC 8422 section 5.11).
    public byte[] DeriveSecret(ReadOnlySpan<byte> peerPublicKey) =>
        _x25519 is { } x25519 ? DeriveX25519(x25519, peerPublicKey) : DeriveEcdh(peerPublicKey);

    // RFC 8446 section 7.4.2 and RFC 8422 section 5.11: an all-zero shared secret means the peer sent a
    // low-order point, and the handshake ends.
    private static byte[] DeriveX25519(X25519DiffieHellman key, ReadOnlySpan<byte> peerPublicKey)
    {
        if (peerPublicKey.Length != X25519DiffieHellman.PublicKeySizeInBytes)
        {
            throw DtlsException.IllegalParameter("the peer's X25519 key share is not 32 bytes");
        }

        byte[] secret = new byte[X25519DiffieHellman.SecretAgreementSizeInBytes];
        try
        {
            key.DeriveRawSecretAgreement(peerPublicKey, secret);
        }
        catch (CryptographicException error)
        {
            throw new DtlsException(
                DtlsAlert.IllegalParameter,
                isRemote: false,
                $"The peer's X25519 key share is not usable: {error.Message}"
            );
        }

        if (!secret.AsSpan().ContainsAnyExcept((byte)0))
        {
            throw DtlsException.IllegalParameter("the X25519 shared secret is all zeros");
        }

        return secret;
    }

    private byte[] DeriveEcdh(ReadOnlySpan<byte> peerPublicKey)
    {
        if (peerPublicKey.Length != 1 + (2 * _coordinateSize) || peerPublicKey[0] != 0x04)
        {
            throw DtlsException.IllegalParameter(
                "the peer's key share is not an uncompressed point of the group"
            );
        }

        ECParameters parameters = new()
        {
            Curve = _curve,
            Q = new ECPoint
            {
                X = peerPublicKey.Slice(1, _coordinateSize).ToArray(),
                Y = peerPublicKey.Slice(1 + _coordinateSize, _coordinateSize).ToArray(),
            },
        };
        try
        {
            using ECDiffieHellman peer = ECDiffieHellman.Create(parameters);
            return _key!.DeriveRawSecretAgreement(peer.PublicKey);
        }
        // Windows reports a point off the curve as PlatformNotSupportedException, the others as
        // CryptographicException.
        catch (Exception error)
            when (error is CryptographicException or PlatformNotSupportedException)
        {
            throw new DtlsException(
                DtlsAlert.IllegalParameter,
                isRemote: false,
                $"The peer's key share is not a valid point: {error.Message}"
            );
        }
    }

    public void Dispose()
    {
        _key?.Dispose();
        _x25519?.Dispose();
    }
}
