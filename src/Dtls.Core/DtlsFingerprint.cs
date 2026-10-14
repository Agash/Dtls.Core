using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.Core;

/// <summary>
/// A certificate fingerprint, as SDP's <c>a=fingerprint</c> carries it (RFC 8122 §5): a hash of the
/// DER certificate. It binds a signalled identity to the certificate the peer presents in the
/// handshake.
/// </summary>
/// <param name="Algorithm">
/// The hash algorithm: SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512, the functions RFC 8122 §5 defines
/// apart from MD5 and MD2, which it forbids for verification.
/// </param>
/// <param name="Hash">The hash of the DER-encoded certificate.</param>
public readonly record struct DtlsFingerprint(
    HashAlgorithmName Algorithm,
    ImmutableArray<byte> Hash
)
{
    /// <summary>The fingerprint of a certificate.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="algorithm">The hash algorithm; SHA-256, which WebRTC requires, by default.</param>
    /// <returns>The fingerprint.</returns>
    public static DtlsFingerprint Compute(
        X509Certificate2 certificate,
        HashAlgorithmName? algorithm = null
    )
    {
        ArgumentNullException.ThrowIfNull(certificate);
        HashAlgorithmName hash = algorithm ?? HashAlgorithmName.SHA256;
        return new DtlsFingerprint(hash, [.. HashData(hash, certificate.RawData)]);
    }

    /// <summary>Whether a certificate has this fingerprint, compared in constant time.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>Whether it matches.</returns>
    public bool Matches(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return !Hash.IsDefaultOrEmpty
            && CryptographicOperations.FixedTimeEquals(
                HashData(Algorithm, certificate.RawData),
                Hash.AsSpan()
            );
    }

    /// <summary>
    /// A certificate validation callback for <see cref="System.Net.Security.SslClientAuthenticationOptions"/> or
    /// <see cref="System.Net.Security.SslServerAuthenticationOptions"/> that accepts exactly the certificate
    /// with this fingerprint, as WebRTC authenticates its peers (RFC 8827 §6.5): the peer's certificate is
    /// self-signed, and the fingerprint signalled out of band is what makes it trusted. Chain errors are
    /// therefore not considered.
    /// </summary>
    /// <returns>The callback.</returns>
    public System.Net.Security.RemoteCertificateValidationCallback CreateValidationCallback()
    {
        DtlsFingerprint expected = this;
        return (_, certificate, _, _) =>
            certificate is X509Certificate2 presented && expected.Matches(presented);
    }

    /// <summary>
    /// A certificate validation callback for a peer that signalled several fingerprints (RFC 8122 §5.1):
    /// of those using the most preferred hash function (SHA-512, then SHA-384, SHA-256, SHA-224, SHA-1),
    /// the presented certificate has to match one. As with <see cref="CreateValidationCallback()"/>, chain
    /// errors are not considered.
    /// </summary>
    /// <param name="fingerprints">The peer's fingerprints.</param>
    /// <returns>The callback; it accepts nothing when <paramref name="fingerprints"/> is empty.</returns>
    public static System.Net.Security.RemoteCertificateValidationCallback CreateValidationCallback(
        IEnumerable<DtlsFingerprint> fingerprints
    )
    {
        ArgumentNullException.ThrowIfNull(fingerprints);
        DtlsFingerprint[] all = [.. fingerprints];
        int best = all.Length == 0 ? -1 : all.Max(static f => Preference(f.Algorithm));
        DtlsFingerprint[] preferred = [.. all.Where(f => Preference(f.Algorithm) == best)];
        return (_, certificate, _, _) =>
            certificate is X509Certificate2 presented
            && preferred.Any(fingerprint => fingerprint.Matches(presented));
    }

    /// <summary>Reads SDP's form: the algorithm name and colon-separated hex, <c>sha-256 AB:CD:...</c>.</summary>
    /// <param name="value">The attribute value.</param>
    /// <param name="fingerprint">The fingerprint.</param>
    /// <returns>Whether it could be read.</returns>
    public static bool TryParse(string? value, out DtlsFingerprint fingerprint)
    {
        fingerprint = default;
        string[] parts = value?.Trim().Split(' ', 2, StringSplitOptions.RemoveEmptyEntries) ?? [];
        if (parts.Length != 2 || AlgorithmOf(parts[0]) is not { } algorithm)
        {
            return false;
        }

        string[] octets = parts[1].Trim().Split(':');
        if (octets.Length != Size(algorithm))
        {
            return false;
        }

        byte[] hash = new byte[octets.Length];
        for (int i = 0; i < octets.Length; i++)
        {
            if (
                octets[i].Length != 2
                || !byte.TryParse(
                    octets[i],
                    System.Globalization.NumberStyles.HexNumber,
                    null,
                    out hash[i]
                )
            )
            {
                return false;
            }
        }

        fingerprint = new DtlsFingerprint(algorithm, [.. hash]);
        return true;
    }

    /// <summary>Reads SDP's form.</summary>
    /// <param name="value">The attribute value.</param>
    /// <returns>The fingerprint.</returns>
    /// <exception cref="FormatException">It is not a fingerprint.</exception>
    public static DtlsFingerprint Parse(string value) =>
        TryParse(value, out DtlsFingerprint fingerprint)
            ? fingerprint
            : throw new FormatException($"\"{value}\" is not a certificate fingerprint.");

    /// <summary>Whether two fingerprints name the same algorithm and hash bytes.</summary>
    /// <param name="other">The other fingerprint.</param>
    /// <returns>Whether they are equal.</returns>
    public bool Equals(DtlsFingerprint other) =>
        Algorithm == other.Algorithm && Hash.AsSpan().SequenceEqual(other.Hash.AsSpan());

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        HashCode hash = default;
        hash.Add(Algorithm);
        hash.AddBytes(Hash.AsSpan());
        return hash.ToHashCode();
    }

    /// <summary>SDP's form: <c>sha-256 AB:CD:...</c>.</summary>
    /// <returns>The attribute value.</returns>
    public override string ToString() =>
        $"{NameOf(Algorithm)} {string.Join(':', Hash.Select(static b => b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture)))}";

    // The BCL names no SHA-224 algorithm.
    private static readonly HashAlgorithmName s_sha224 = new("SHA224");

    private static byte[] HashData(HashAlgorithmName algorithm, ReadOnlySpan<byte> data) =>
        algorithm == HashAlgorithmName.SHA256 ? SHA256.HashData(data)
        : algorithm == HashAlgorithmName.SHA384 ? SHA384.HashData(data)
        : algorithm == HashAlgorithmName.SHA512 ? SHA512.HashData(data)
        : algorithm == s_sha224 ? Sha224.HashData(data)
        : algorithm == HashAlgorithmName.SHA1 ? Sha1(data)
        : throw new ArgumentException(
            $"{algorithm} is not a fingerprint algorithm Dtls.Core supports.",
            nameof(algorithm)
        );

#pragma warning disable CA5350 // RFC 8122 section 5 keeps SHA-1 for fingerprints; only MD5 and MD2 are forbidden.
    private static byte[] Sha1(ReadOnlySpan<byte> data) => SHA1.HashData(data);
#pragma warning restore CA5350

    private static int Size(HashAlgorithmName algorithm) =>
        algorithm == HashAlgorithmName.SHA1 ? 20
        : algorithm == s_sha224 ? Sha224.HashSize
        : algorithm == HashAlgorithmName.SHA256 ? 32
        : algorithm == HashAlgorithmName.SHA384 ? 48
        : 64;

    // Stronger first, for choosing among a peer's fingerprints (RFC 8122 §5.1).
    private static int Preference(HashAlgorithmName algorithm) =>
        algorithm == HashAlgorithmName.SHA512 ? 5
        : algorithm == HashAlgorithmName.SHA384 ? 4
        : algorithm == HashAlgorithmName.SHA256 ? 3
        : algorithm == s_sha224 ? 2
        : 1;

    [SuppressMessage(
        "Globalization",
        "CA1308",
        Justification = "SDP names the hash functions in lower case."
    )]
    private static string NameOf(HashAlgorithmName algorithm) =>
        algorithm == HashAlgorithmName.SHA1 ? "sha-1"
        : algorithm == s_sha224 ? "sha-224"
        : algorithm == HashAlgorithmName.SHA256 ? "sha-256"
        : algorithm == HashAlgorithmName.SHA384 ? "sha-384"
        : algorithm == HashAlgorithmName.SHA512 ? "sha-512"
        : algorithm.Name?.ToLowerInvariant() ?? "unknown";

    private static HashAlgorithmName? AlgorithmOf(string name) =>
        name.ToUpperInvariant() switch
        {
            "SHA-1" => HashAlgorithmName.SHA1,
            "SHA-224" => s_sha224,
            "SHA-256" => HashAlgorithmName.SHA256,
            "SHA-384" => HashAlgorithmName.SHA384,
            "SHA-512" => HashAlgorithmName.SHA512,
            // MD5 and MD2 are recognised by RFC 8122 section 5 only to be refused.
            _ => null,
        };
}
