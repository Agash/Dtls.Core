namespace Dtls.NET;

/// <summary>
/// An SRTP protection profile negotiated with DTLS-SRTP's <c>use_srtp</c> extension (RFC 5764 §4.1.2,
/// RFC 7714 §14.2). The values are the IANA code points.
/// </summary>
public enum SrtpProtectionProfile : ushort
{
    /// <summary><c>SRTP_AES128_CM_HMAC_SHA1_80</c>: AES counter mode with an 80-bit HMAC-SHA1 tag.</summary>
    Aes128CmHmacSha180 = 0x0001,

    /// <summary><c>SRTP_AES128_CM_HMAC_SHA1_32</c>: AES counter mode with a 32-bit HMAC-SHA1 tag.</summary>
    Aes128CmHmacSha132 = 0x0002,

    /// <summary><c>SRTP_AEAD_AES_128_GCM</c>.</summary>
    AeadAes128Gcm = 0x0007,

    /// <summary><c>SRTP_AEAD_AES_256_GCM</c>.</summary>
    AeadAes256Gcm = 0x0008,
}

/// <summary>
/// The SRTP master keys and salts a DTLS-SRTP handshake exports for its negotiated profile (RFC 5764
/// §4.2), one pair per direction.
/// </summary>
/// <remarks>These are secrets: keep them only as long as the SRTP session needs them.</remarks>
/// <param name="Profile">The negotiated protection profile.</param>
/// <param name="ClientMasterKey">The master key for what the DTLS client sends.</param>
/// <param name="ClientMasterSalt">The master salt for what the DTLS client sends.</param>
/// <param name="ServerMasterKey">The master key for what the DTLS server sends.</param>
/// <param name="ServerMasterSalt">The master salt for what the DTLS server sends.</param>
public sealed record SrtpKeyingMaterial(
    SrtpProtectionProfile Profile,
    ReadOnlyMemory<byte> ClientMasterKey,
    ReadOnlyMemory<byte> ClientMasterSalt,
    ReadOnlyMemory<byte> ServerMasterKey,
    ReadOnlyMemory<byte> ServerMasterSalt
)
{
    // The exporter label for DTLS-SRTP (RFC 5764 §4.2).
    internal const string ExporterLabel = "EXTRACTOR-dtls_srtp";

    // The master key and salt lengths of a profile (RFC 3711, RFC 7714).
    internal static (int Key, int Salt) Lengths(SrtpProtectionProfile profile) =>
        profile switch
        {
            SrtpProtectionProfile.Aes128CmHmacSha180 or SrtpProtectionProfile.Aes128CmHmacSha132 =>
                (16, 14),
            SrtpProtectionProfile.AeadAes128Gcm => (16, 12),
            SrtpProtectionProfile.AeadAes256Gcm => (32, 12),
            _ => throw new ArgumentOutOfRangeException(
                nameof(profile),
                profile,
                "Not an SRTP profile Dtls.NET knows."
            ),
        };

    // Splits exported keying material, laid out client key, server key, client salt, server salt.
    internal static SrtpKeyingMaterial Split(
        SrtpProtectionProfile profile,
        ReadOnlySpan<byte> material
    )
    {
        (int key, int salt) = Lengths(profile);
        return new SrtpKeyingMaterial(
            profile,
            material[..key].ToArray(),
            material.Slice(2 * key, salt).ToArray(),
            material.Slice(key, key).ToArray(),
            material.Slice((2 * key) + salt, salt).ToArray()
        );
    }
}
