using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Dtls.Core.Tests;

// Windows' own DTLS 1.2, Schannel, driven through SSPI as a peer for the interop tests. It runs the
// handshake over an IDatagramTransport, asks for DTLS-SRTP and the SRTP keying material exporter, and
// protects application data with EncryptMessage and DecryptMessage.
[SupportedOSPlatform("windows")]
internal sealed class SchannelPeer : IDisposable
{
    public const string ExporterLabel = "EXTRACTOR-dtls_srtp";
    public const int KeyingMaterialLength = 60;

    private const uint SecpkgCredInbound = 1;
    private const uint SecpkgCredOutbound = 2;
    private const uint SchannelCredVersion = 4;
    private const uint SpProtDtls12Server = 0x00040000;
    private const uint SpProtDtls12Client = 0x00080000;
    private const uint SchCredManualCredValidation = 0x00000008;
    private const uint SchCredNoDefaultCreds = 0x00000010;

    private const uint IscReqConfidentiality = 0x00000010;
    private const uint IscReqUseSuppliedCreds = 0x00000080;
    private const uint IscReqAllocateMemory = 0x00000100;
    private const uint IscReqDatagram = 0x00000400;
    private const uint IscReqExtendedError = 0x00004000;
    private const uint IscReqManualCredValidation = 0x00080000;
    private const uint AscReqMutualAuth = 0x00000002;
    private const uint AscReqConfidentiality = 0x00000010;
    private const uint AscReqAllocateMemory = 0x00000100;
    private const uint AscReqDatagram = 0x00000400;
    private const uint AscReqExtendedError = 0x00008000;

    private const uint SecbufferEmpty = 0;
    private const uint SecbufferData = 1;
    private const uint SecbufferToken = 2;
    private const uint SecbufferExtra = 5;
    private const uint SecbufferStreamTrailer = 6;
    private const uint SecbufferStreamHeader = 7;
    private const uint SecbufferAlert = 17;
    private const uint SecbufferSrtpProtectionProfiles = 19;

    private const uint SecpkgAttrStreamSizes = 4;
    private const uint SecpkgAttrRemoteCertContext = 0x53;
    private const uint SecpkgAttrCipherInfo = 0x64;
    private const uint SecpkgAttrKeyingMaterialInfo = 0x6a;
    private const uint SecpkgAttrKeyingMaterial = 0x6b;
    private const uint SecpkgAttrSrtpParameters = 0x6c;

    private const int SecEOk = 0;
    private const int SecIContinueNeeded = 0x00090312;
    private const int SecIMessageFragment = 0x00090364;
    private const int SecEInvalidHandle = unchecked((int)0x80090301);

    // A DTLS server binds its cookie to the client's address, which SSPI takes as a SOCKADDR in a
    // SECBUFFER_EXTRA input buffer. The in-memory path has no address, so a fixed one stands in.
    private static readonly byte[] s_clientAddress =
    [
        2,
        0,
        0x30,
        0x39,
        127,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];

    private readonly IDatagramTransport _transport;
    private readonly X509Certificate2 _certificate;
    private SecHandle _credential;
    private SecHandle _context;
    private bool _hasContext;
    private bool _keyingMaterialRequested;

    private SchannelPeer(IDatagramTransport transport, X509Certificate2 certificate)
    {
        _transport = transport;
        _certificate = certificate;
    }

    public ushort SrtpProfile { get; private set; }

    public int CipherSuite { get; private set; }

    public byte[] KeyingMaterial { get; private set; } = [];

    public byte[]? RemoteCertificate { get; private set; }

    public static Task<SchannelPeer> ConnectAsync(
        IDatagramTransport transport,
        X509Certificate2 certificate,
        ushort[] srtpProfiles,
        List<string> trace,
        CancellationToken cancellationToken
    ) =>
        HandshakeAsync(
            transport,
            certificate,
            srtpProfiles,
            server: false,
            trace,
            cancellationToken
        );

    public static Task<SchannelPeer> AcceptAsync(
        IDatagramTransport transport,
        X509Certificate2 certificate,
        ushort[] srtpProfiles,
        List<string> trace,
        CancellationToken cancellationToken
    ) =>
        HandshakeAsync(
            transport,
            certificate,
            srtpProfiles,
            server: true,
            trace,
            cancellationToken
        );

    public async Task SendAsync(byte[] data, CancellationToken cancellationToken)
    {
        byte[] datagram = Encrypt(data);
        await _transport.SendAsync(datagram, cancellationToken);
    }

    public async Task<byte[]> ReceiveAsync(CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[65535];
        while (true)
        {
            int length = await _transport.ReceiveAsync(buffer, cancellationToken);
            byte[]? data = Decrypt(buffer.AsSpan(0, length));
            if (data is not null)
            {
                return data;
            }
        }
    }

    public void Dispose()
    {
        if (_hasContext)
        {
            _ = DeleteSecurityContext(ref _context);
        }

        _ = FreeCredentialsHandle(ref _credential);
    }

    private static async Task<SchannelPeer> HandshakeAsync(
        IDatagramTransport transport,
        X509Certificate2 certificate,
        ushort[] srtpProfiles,
        bool server,
        List<string> trace,
        CancellationToken cancellationToken
    )
    {
        SchannelPeer peer = new(transport, certificate);
        try
        {
            peer.AcquireCredentials(server);
            byte[] buffer = new byte[65535];
            byte[]? input = null;
            if (server)
            {
                // A server starts from the client's first datagram.
                int first = await transport.ReceiveAsync(buffer, cancellationToken);
                input = buffer[..first];
            }

            while (true)
            {
                (int status, List<byte[]> output) = peer.Step(input, srtpProfiles, server);
                lock (trace)
                {
                    trace.Add(
                        $"in {input?.Length ?? -1} -> 0x{status:X8} out [{string.Join(",", output.Select(o => o.Length))}]"
                    );
                }

                foreach (byte[] datagram in output)
                {
                    await transport.SendAsync(datagram, cancellationToken);
                }

                if (status == SecEOk)
                {
                    peer.ReadResults();
                    return peer;
                }

                if (status != SecIContinueNeeded)
                {
                    throw new Win32Exception(
                        status,
                        $"Schannel's handshake failed with 0x{status:X8}."
                    );
                }

                int length = await transport.ReceiveAsync(buffer, cancellationToken);
                input = buffer[..length];
            }
        }
        catch (Exception error)
        {
            lock (trace)
            {
                trace.Add(error.Message);
            }

            peer.Dispose();
            throw;
        }
    }

    private unsafe void AcquireCredentials(bool server)
    {
        CertContext* certificate = (CertContext*)_certificate.Handle;
        SchannelCred credential = new()
        {
            Version = SchannelCredVersion,
            CredentialCount = 1,
            Credentials = (nint)(&certificate),
            EnabledProtocols = server ? SpProtDtls12Server : SpProtDtls12Client,
            Flags = server ? 0 : SchCredManualCredValidation | SchCredNoDefaultCreds,
        };
        long expiry;
        int status = AcquireCredentialsHandleW(
            null,
            "Microsoft Unified Security Protocol Provider",
            server ? SecpkgCredInbound : SecpkgCredOutbound,
            0,
            &credential,
            0,
            0,
            out _credential,
            &expiry
        );
        GC.KeepAlive(_certificate);
        if (status != SecEOk)
        {
            throw new Win32Exception(
                status,
                $"AcquireCredentialsHandle failed with 0x{status:X8}."
            );
        }
    }

    // One call into the handshake with a received datagram (none for the first); returns the status and
    // the datagrams to send, following SEC_I_MESSAGE_FRAGMENT until the flight is complete.
    private unsafe (int Status, List<byte[]> Output) Step(
        byte[]? input,
        ushort[] srtpProfiles,
        bool server
    )
    {
        List<byte[]> output = [];
        byte[] profiles = SrtpProfilesBuffer(srtpProfiles);
        while (true)
        {
            fixed (byte* inputBytes = input)
            fixed (byte* profileBytes = profiles)
            fixed (byte* addressBytes = s_clientAddress)
            {
                SecBuffer* inBuffers = stackalloc SecBuffer[4];
                int inCount = 0;
                if (input is not null)
                {
                    inBuffers[inCount++] = new SecBuffer(SecbufferToken, input.Length, inputBytes);
                    inBuffers[inCount++] = new SecBuffer(SecbufferEmpty, 0, null);
                    if (server)
                    {
                        inBuffers[inCount++] = new SecBuffer(
                            SecbufferExtra,
                            s_clientAddress.Length,
                            addressBytes
                        );
                    }
                }
                else if (!_hasContext && srtpProfiles.Length > 0 && !server)
                {
                    inBuffers[inCount++] = new SecBuffer(
                        SecbufferSrtpProtectionProfiles,
                        profiles.Length,
                        profileBytes
                    );
                }

                // Every call until the handshake is done: after a HelloVerifyRequest the context that answers is new.
                if (server && input is not null && srtpProfiles.Length > 0)
                {
                    inBuffers[inCount++] = new SecBuffer(
                        SecbufferSrtpProtectionProfiles,
                        profiles.Length,
                        profileBytes
                    );
                }

                SecBufferDesc inDesc = new(inBuffers, inCount);
                SecBuffer* outBuffers = stackalloc SecBuffer[2];
                outBuffers[0] = new SecBuffer(SecbufferToken, 0, null);
                outBuffers[1] = new SecBuffer(SecbufferAlert, 0, null);
                SecBufferDesc outDesc = new(outBuffers, 2);
                uint attributes;
                long expiry;
                int status;
                SecHandle context = _context;
                if (server)
                {
                    status = AcceptSecurityContext(
                        ref _credential,
                        _hasContext ? &context : null,
                        inCount > 0 ? &inDesc : null,
                        AscReqDatagram
                            | AscReqConfidentiality
                            | AscReqAllocateMemory
                            | AscReqExtendedError
                            | AscReqMutualAuth,
                        0,
                        ref _context,
                        &outDesc,
                        &attributes,
                        &expiry
                    );
                }
                else
                {
                    status = InitializeSecurityContextW(
                        ref _credential,
                        _hasContext ? &context : null,
                        null,
                        IscReqDatagram
                            | IscReqConfidentiality
                            | IscReqAllocateMemory
                            | IscReqExtendedError
                            | IscReqManualCredValidation
                            | IscReqUseSuppliedCreds,
                        0,
                        0,
                        inCount > 0 ? &inDesc : null,
                        0,
                        ref _context,
                        &outDesc,
                        &attributes,
                        &expiry
                    );
                }

                // A server answering with a HelloVerifyRequest keeps no context yet: it exists once the handle does.
                _hasContext = _context.Lower != 0 || _context.Upper != 0;
                if (_hasContext && !_keyingMaterialRequested)
                {
                    RequestKeyingMaterial();
                }

                for (int i = 0; i < 2; i++)
                {
                    if (outBuffers[i].Buffer is not null)
                    {
                        if (outBuffers[i].Type == SecbufferToken && outBuffers[i].Size > 0)
                        {
                            output.Add(
                                new ReadOnlySpan<byte>(
                                    outBuffers[i].Buffer,
                                    (int)outBuffers[i].Size
                                ).ToArray()
                            );
                        }

                        _ = FreeContextBuffer(outBuffers[i].Buffer);
                    }
                }

                if (
                    input is not null
                    && inCount > 1
                    && inBuffers[1].Type == SecbufferExtra
                    && inBuffers[1].Size > 0
                )
                {
                    input = input[^(int)inBuffers[1].Size..];
                    continue;
                }

                if (status == SecIMessageFragment)
                {
                    input = null;
                    continue;
                }

                return (status, output);
            }
        }
    }

    // The exporter has to be asked for before the handshake completes (SECPKG_ATTR_KEYING_MATERIAL_INFO).
    private unsafe void RequestKeyingMaterial()
    {
        byte[] label = Encoding.ASCII.GetBytes(ExporterLabel + "\0");
        fixed (byte* labelBytes = label)
        {
            KeyingMaterialInfo info = new()
            {
                LabelSize = (ushort)label.Length,
                Label = labelBytes,
                KeyingMaterialSize = KeyingMaterialLength,
            };
            int status = SetContextAttributesW(
                ref _context,
                SecpkgAttrKeyingMaterialInfo,
                &info,
                (uint)sizeof(KeyingMaterialInfo)
            );
            // Until the cookie exchange is over a server's context cannot take it yet; the next step asks again.
            _keyingMaterialRequested = status == SecEOk;
            if (status is not (SecEOk or SecEInvalidHandle))
            {
                throw new Win32Exception(
                    status,
                    $"Setting the keying material exporter failed with 0x{status:X8}."
                );
            }
        }
    }

    private unsafe void ReadResults()
    {
        KeyingMaterialResult material;
        int status = QueryContextAttributesW(ref _context, SecpkgAttrKeyingMaterial, &material);
        if (status == SecEOk)
        {
            KeyingMaterial = new ReadOnlySpan<byte>(
                material.Material,
                (int)material.Size
            ).ToArray();
            _ = FreeContextBuffer(material.Material);
        }

        SrtpParameters srtp;
        if (QueryContextAttributesW(ref _context, SecpkgAttrSrtpParameters, &srtp) == SecEOk)
        {
            // SSPI carries SRTP profiles in network byte order, as they are on the wire.
            SrtpProfile = System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(
                srtp.ProtectionProfile
            );
            if (srtp.MasterKeyIdentifier is not null)
            {
                _ = FreeContextBuffer(srtp.MasterKeyIdentifier);
            }
        }

        CipherInfo cipher = new() { Version = 1 };
        if (QueryContextAttributesW(ref _context, SecpkgAttrCipherInfo, &cipher) == SecEOk)
        {
            CipherSuite = (int)cipher.CipherSuite;
        }

        void* remote;
        if (
            QueryContextAttributesW(ref _context, SecpkgAttrRemoteCertContext, &remote) == SecEOk
            && remote is not null
        )
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(
                new X509Certificate2((nint)remote).RawData
            );
            RemoteCertificate = certificate.RawData;
            _ = CertFreeCertificateContext(remote);
        }
    }

    private unsafe byte[] Encrypt(byte[] data)
    {
        StreamSizes sizes;
        int status = QueryContextAttributesW(ref _context, SecpkgAttrStreamSizes, &sizes);
        if (status != SecEOk)
        {
            throw new Win32Exception(
                status,
                $"Querying the stream sizes failed with 0x{status:X8}."
            );
        }

        byte[] message = new byte[sizes.Header + data.Length + sizes.Trailer];
        data.CopyTo(message, (int)sizes.Header);
        fixed (byte* bytes = message)
        {
            SecBuffer* buffers = stackalloc SecBuffer[4];
            buffers[0] = new SecBuffer(SecbufferStreamHeader, (int)sizes.Header, bytes);
            buffers[1] = new SecBuffer(SecbufferData, data.Length, bytes + sizes.Header);
            buffers[2] = new SecBuffer(
                SecbufferStreamTrailer,
                (int)sizes.Trailer,
                bytes + sizes.Header + data.Length
            );
            buffers[3] = new SecBuffer(SecbufferEmpty, 0, null);
            SecBufferDesc desc = new(buffers, 4);
            status = EncryptMessage(ref _context, 0, &desc, 0);
            if (status != SecEOk)
            {
                throw new Win32Exception(status, $"EncryptMessage failed with 0x{status:X8}.");
            }

            return message[..(int)(buffers[0].Size + buffers[1].Size + buffers[2].Size)];
        }
    }

    // The plaintext of a datagram, or null when it held no application data.
    private unsafe byte[]? Decrypt(Span<byte> datagram)
    {
        fixed (byte* bytes = datagram)
        {
            SecBuffer* buffers = stackalloc SecBuffer[4];
            buffers[0] = new SecBuffer(SecbufferData, datagram.Length, bytes);
            buffers[1] = new SecBuffer(SecbufferEmpty, 0, null);
            buffers[2] = new SecBuffer(SecbufferEmpty, 0, null);
            buffers[3] = new SecBuffer(SecbufferEmpty, 0, null);
            SecBufferDesc desc = new(buffers, 4);
            int status = DecryptMessage(ref _context, &desc, 0, null);
            if (status != SecEOk)
            {
                throw new Win32Exception(status, $"DecryptMessage failed with 0x{status:X8}.");
            }

            for (int i = 0; i < 4; i++)
            {
                if (buffers[i].Type == SecbufferData)
                {
                    return new ReadOnlySpan<byte>(
                        buffers[i].Buffer,
                        (int)buffers[i].Size
                    ).ToArray();
                }
            }

            return null;
        }
    }

    // SEC_SRTP_PROTECTION_PROFILES: the list's size in bytes, then the profiles in network byte order.
    private static byte[] SrtpProfilesBuffer(ushort[] profiles)
    {
        byte[] buffer = new byte[2 + (2 * profiles.Length)];
        MemoryMarshal.Write(buffer, (ushort)(2 * profiles.Length));
        for (int i = 0; i < profiles.Length; i++)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(
                buffer.AsSpan(2 + (2 * i)),
                profiles[i]
            );
        }
        return buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecHandle
    {
        public nuint Lower;
        public nuint Upper;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct SecBuffer(uint type, int size, void* buffer)
    {
        public uint Size = (uint)size;
        public uint Type = type;
        public byte* Buffer = (byte*)buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct SecBufferDesc(SecBuffer* buffers, int count)
    {
        public uint Version = 0;
        public uint Count = (uint)count;
        public SecBuffer* Buffers = buffers;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SchannelCred
    {
        public uint Version;
        public uint CredentialCount;
        public nint Credentials;
        public nint RootStore;
        public uint MapperCount;
        public nint Mappers;
        public uint SupportedAlgorithmCount;
        public nint SupportedAlgorithms;
        public uint EnabledProtocols;
        public uint MinimumCipherStrength;
        public uint MaximumCipherStrength;
        public uint SessionLifespan;
        public uint Flags;
        public uint CredentialFormat;
    }

    private struct CertContext;

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct KeyingMaterialInfo
    {
        public ushort LabelSize;
        public byte* Label;
        public ushort ContextValueSize;
        public byte* ContextValue;
        public uint KeyingMaterialSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct KeyingMaterialResult
    {
        public uint Size;
        public byte* Material;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct SrtpParameters
    {
        public ushort ProtectionProfile;
        public byte MasterKeyIdentifierSize;
        public byte* MasterKeyIdentifier;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StreamSizes
    {
        public uint Header;
        public uint Trailer;
        public uint MaximumMessage;
        public uint Buffers;
        public uint BlockSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct CipherInfo
    {
        public uint Version;
        public uint Protocol;
        public uint CipherSuite;
        public uint BaseCipherSuite;
        public fixed char CipherSuiteName[64];
        public fixed char Cipher[64];
        public uint CipherLength;
        public uint CipherBlockLength;
        public fixed char Hash[64];
        public uint HashLength;
        public fixed char Exchange[64];
        public uint MinimumExchangeLength;
        public uint MaximumExchangeLength;
        public fixed char Certificate[64];
        public uint KeyType;
    }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    private static extern unsafe int AcquireCredentialsHandleW(
        string? principal,
        string package,
        uint credentialUse,
        nint logonId,
        void* authenticationData,
        nint getKeyFunction,
        nint getKeyArgument,
        out SecHandle credential,
        long* expiry
    );

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    private static extern unsafe int InitializeSecurityContextW(
        ref SecHandle credential,
        SecHandle* context,
        string? targetName,
        uint contextRequirements,
        uint reserved1,
        uint targetDataRepresentation,
        SecBufferDesc* input,
        uint reserved2,
        ref SecHandle newContext,
        SecBufferDesc* output,
        uint* contextAttributes,
        long* expiry
    );

    [DllImport("secur32.dll")]
    private static extern unsafe int AcceptSecurityContext(
        ref SecHandle credential,
        SecHandle* context,
        SecBufferDesc* input,
        uint contextRequirements,
        uint targetDataRepresentation,
        ref SecHandle newContext,
        SecBufferDesc* output,
        uint* contextAttributes,
        long* expiry
    );

    [DllImport("secur32.dll")]
    private static extern unsafe int QueryContextAttributesW(
        ref SecHandle context,
        uint attribute,
        void* buffer
    );

    [DllImport("secur32.dll")]
    private static extern unsafe int SetContextAttributesW(
        ref SecHandle context,
        uint attribute,
        void* info,
        uint size
    );

    [DllImport("secur32.dll")]
    private static extern unsafe int EncryptMessage(
        ref SecHandle context,
        uint qualityOfProtection,
        SecBufferDesc* message,
        uint sequence
    );

    [DllImport("secur32.dll")]
    private static extern unsafe int DecryptMessage(
        ref SecHandle context,
        SecBufferDesc* message,
        uint sequence,
        uint* qualityOfProtection
    );

    [DllImport("secur32.dll")]
    private static extern unsafe int FreeContextBuffer(void* buffer);

    [DllImport("secur32.dll")]
    private static extern unsafe int DeleteSecurityContext(ref SecHandle context);

    [DllImport("secur32.dll")]
    private static extern unsafe int FreeCredentialsHandle(ref SecHandle credential);

    [DllImport("crypt32.dll")]
    private static extern unsafe int CertFreeCertificateContext(void* context);
}
