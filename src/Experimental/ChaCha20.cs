using System;
using System.Diagnostics;
using System.Buffers;
using System.Threading;
using NSec.Cryptography;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Experimental
{
    public class ChaCha20: StreamCipherAlgorithm
    {
        private const uint NSecBlobHeader = 0xDE6541DE;

        private static int s_selfTest;

        public ChaCha20(): base(
            keySize: crypto_stream_chacha20_ietf_KEYBYTES,
            nonceSize: crypto_stream_chacha20_ietf_NONCEBYTES)
        {
            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }

        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKey publicKey)
        {
            Debug.Assert(seed.Length == crypto_stream_chacha20_ietf_KEYBYTES);
            publicKey = null;
            owner = memoryPool.Rent(seed.Length);
            memory = owner.Memory.Slice(0, seed.Length);
            seed.CopyTo(owner.Memory.Span);
        }

        private protected unsafe override void GeneratePseudoRandomStreamCore (
            ReadOnlySpan<byte> key,
            in Nonce nonce,
            Span<byte> stream)
        {
            Debug.Assert(key.Length == crypto_stream_chacha20_ietf_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_stream_chacha20_ietf_NONCEBYTES);

            var clen = (ulong)stream.Length;
            fixed (byte* c = stream)
            fixed (Nonce* n = &nonce)
            fixed (byte* k = key)
            {
                int error = crypto_stream_chacha20_ietf(
                    c,
                    clen,
                    n,
                    k);

                Debug.Assert(error == 0);
                Debug.Assert((ulong)stream.Length == clen);
            }
        }

        private protected unsafe override void XOrCore(ReadOnlySpan<byte> key, in Nonce nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
        {
            Debug.Assert(key.Length == crypto_stream_chacha20_ietf_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_stream_chacha20_ietf_NONCEBYTES);

            var mlen = (ulong)plaintext.Length;
            fixed (byte* c = ciphertext)
            fixed (byte* m = plaintext)
            fixed (Nonce* n = & nonce)
            fixed (byte* k = key)
            {
                int error = crypto_stream_chacha20_ietf_xor(
                    c,
                    m,
                    mlen,
                    n,
                    k
                );
                Debug.Assert(error == 0);
                Debug.Assert((ulong)ciphertext.Length == mlen);
            }
        }
        private protected unsafe override void XOrICCore(ReadOnlySpan<byte> key, in Nonce nonce, ReadOnlySpan<byte> plaintext, uint ic, Span<byte> ciphertext)
        {
            Debug.Assert(key.Length == crypto_stream_chacha20_ietf_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_stream_chacha20_ietf_NONCEBYTES);

            var mlen = (ulong)plaintext.Length;
            fixed (byte* c = ciphertext)
            fixed (byte* m = plaintext)
            fixed (Nonce* n = & nonce)
            fixed (byte* k = key)
            {
                int error = crypto_stream_chacha20_ietf_xor_ic(
                    c,
                    m,
                    mlen,
                    n,
                    (UIntPtr)ic,
                    k
                );
                Debug.Assert(error == 0);
                Debug.Assert((ulong)ciphertext.Length == mlen);
            }
        }


        internal override bool TryExportKey(ReadOnlySpan<byte> key, KeyBlobFormat format, Span<byte> blob, out int blobSize)
        {
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return RawKeyFormatter.TryExport(key, blob, out blobSize);
            case KeyBlobFormat.NSecSymmetricKey:
                return NSecKeyFormatter.TryExport(NSecBlobHeader, KeySize, 0, key, blob, out blobSize);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryImportKey(ReadOnlySpan<byte> blob, KeyBlobFormat format, MemoryPool<byte> memoryPool, out ReadOnlyMemory<byte> memory, out IMemoryOwner<byte> owner, out PublicKey publicKey)
        {
            publicKey = null;

            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return RawKeyFormatter.TryImport(KeySize, blob, memoryPool, out memory, out owner);
            case KeyBlobFormat.NSecSymmetricKey:
                return NSecKeyFormatter.TryImport(NSecBlobHeader, KeySize, 0, blob, memoryPool, out memory, out owner);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override int GetSeedSize()
        {
            return crypto_stream_chacha20_ietf_KEYBYTES;
        }

        private static void SelfTest()
        {
            if ((crypto_stream_chacha20_ietf_keybytes() != (UIntPtr)crypto_stream_chacha20_ietf_KEYBYTES) ||
                (crypto_stream_chacha20_ietf_noncebytes() != (UIntPtr)crypto_stream_chacha20_ietf_NONCEBYTES))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }

    }
}
