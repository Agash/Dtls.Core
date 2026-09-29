using System.Security.Cryptography;
using Dtls.NET.Crypto;
using Dtls.NET.Handshake;
using Dtls.NET.Records;

namespace Dtls.NET.Protocol;

// The key schedule as both sides run it: the master secret, epoch 1's keys and the Finished messages.
internal sealed partial class DtlsProtocol
{
    private bool _extendedMasterSecret;
    private byte[]? _premasterSecret;
    private RecordCipher? _pendingWrite;

    // The master secret and epoch 1's keys, once the client's key exchange is in the transcript. The
    // new read keys wait for the peer's ChangeCipherSpec; a client writes with its new keys at once,
    // a server only after the client's Finished.
    private void DeriveKeys()
    {
        (byte[] client, byte[] server) = Randoms;
        byte[] sessionHash = _transcript.Hash(_suite.PrfHash);
        _masterSecret = KeySchedule.MasterSecret(
            _suite,
            _premasterSecret,
            _extendedMasterSecret,
            sessionHash,
            client,
            server
        );
        CryptographicOperations.ZeroMemory(_premasterSecret);
        _premasterSecret = null;
        (RecordCipher clientCipher, RecordCipher serverCipher) = KeySchedule.RecordCiphers(
            _suite,
            _masterSecret,
            client,
            server
        );
        if (Role == DtlsRole.Client)
        {
            _records.InstallWrite(clientCipher);
            _pendingRead = serverCipher;
        }
        else
        {
            _pendingWrite = serverCipher;
            _pendingRead = clientCipher;
        }
    }

    // This side's Finished over the transcript so far, which then joins it.
    private HandshakeMessage FinishedMessage(bool fromClient)
    {
        byte[] verifyData = KeySchedule.VerifyData(
            _suite,
            _masterSecret,
            fromClient,
            _transcript.Hash(_suite.PrfHash)
        );
        HandshakeMessage finished = NewMessage(
            HandshakeType.Finished,
            w => w.WriteBytes(verifyData)
        );
        _transcript.Add(finished);
        return finished;
    }

    // Checks the peer's Finished against the transcript before it, then adds it.
    private void ReceiveFinished(HandshakeMessage message, bool fromClient)
    {
        byte[] expected = KeySchedule.VerifyData(
            _suite,
            _masterSecret,
            fromClient,
            _transcript.Hash(_suite.PrfHash)
        );
        if (!CryptographicOperations.FixedTimeEquals(expected, message.Body))
        {
            throw DtlsException.DecryptError("the peer's Finished does not match the handshake");
        }

        _transcript.Add(message);
    }
}
