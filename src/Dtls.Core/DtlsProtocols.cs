namespace Dtls.Core;

/// <summary>The DTLS versions a connection may use.</summary>
[Flags]
public enum DtlsProtocols
{
    /// <summary>None.</summary>
    None = 0,

    /// <summary>DTLS 1.2 (RFC 6347).</summary>
    Dtls12 = 1,

    /// <summary>DTLS 1.3 (RFC 9147).</summary>
    Dtls13 = 2,
}
