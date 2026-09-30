using System.Security.Cryptography;
using Dtls.Core.Handshake;

namespace Dtls.Core.Crypto;

// An ephemeral ECDHE key pair on a named group (RFC 8422). The public key goes on the wire as an
// uncompressed point (0x04 || X || Y, RFC 8422 §5.4.1); the premaster secret is the shared point's x
// coordinate (RFC 8422 §5.10).
internal sealed class KeyShare : IDisposable
{
    private readonly ECDiffieHellman _key;
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

    public NamedGroup Group { get; }

    public byte[] PublicKey { get; }

    // The groups this platform can run, most preferred first.
    public static IEnumerable<NamedGroup> SupportedGroups
    {
        get
        {
            yield return NamedGroup.Secp256r1;
            yield return NamedGroup.Secp384r1;
        }
    }

    public static bool IsSupported(NamedGroup group) =>
        group is NamedGroup.Secp256r1 or NamedGroup.Secp384r1;

    public static KeyShare Create(NamedGroup group) =>
        group switch
        {
            NamedGroup.Secp256r1 => new KeyShare(group, ECCurve.NamedCurves.nistP256, 32),
            NamedGroup.Secp384r1 => new KeyShare(group, ECCurve.NamedCurves.nistP384, 48),
            _ => throw DtlsException.IllegalParameter($"the group {group} is not supported"),
        };

    // The premaster secret with a peer's public key. The point is decoded strictly and validated by
    // the platform on import, so an invalid or off-curve point fails here (RFC 8422 §5.11).
    public byte[] DeriveSecret(ReadOnlySpan<byte> peerPublicKey)
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
            return _key.DeriveRawSecretAgreement(peer.PublicKey);
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

    public void Dispose() => _key.Dispose();
}
