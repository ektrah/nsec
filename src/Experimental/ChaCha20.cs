using System;
using System.Buffers;
using System.Diagnostics;
using System.Threading;
using NSec.Cryptography;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Experimental
{
    public class ChaCha20 : StreamCipherAlgorithm
    {
        private static int s_selfTest;

        public ChaCha20() : base(
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
            out PublicKey? publicKey)
        {
            Debug.Assert(seed.Length == crypto_stream_chacha20_ietf_KEYBYTES);

            publicKey = null;
            owner = memoryPool.Rent(seed.Length);
            memory = owner.Memory.Slice(0, seed.Length);
            seed.CopyTo(owner.Memory.Span);
        }

        internal override int GetSeedSize()
        {
            return crypto_stream_chacha20_ietf_KEYBYTES;
        }

        private protected unsafe override void GeneratePseudoRandomStreamCore(
            ReadOnlySpan<byte> key,
            in Nonce nonce,
            Span<byte> bytes)
        {
            Debug.Assert(key.Length == crypto_stream_chacha20_ietf_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_stream_chacha20_ietf_NONCEBYTES);

            fixed (byte* c = bytes)
            fixed (Nonce* n = &nonce)
            fixed (byte* k = key)
            {
                int error = crypto_stream_chacha20_ietf(
                    c,
                    (ulong)bytes.Length,
                    n,
                    k);

                Debug.Assert(error == 0);
            }
        }

        private protected unsafe override void XOrCore(
            ReadOnlySpan<byte> key,
            in Nonce nonce,
            ReadOnlySpan<byte> input,
            Span<byte> output)
        {
            Debug.Assert(key.Length == crypto_stream_chacha20_ietf_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_stream_chacha20_ietf_NONCEBYTES);
            Debug.Assert(output.Length == input.Length);

            fixed (byte* c = output)
            fixed (byte* m = input)
            fixed (Nonce* n = &nonce)
            fixed (byte* k = key)
            {
                int error = crypto_stream_chacha20_ietf_xor(
                    c,
                    m,
                    (ulong)input.Length,
                    n,
                    k);

                Debug.Assert(error == 0);
            }
        }

        private protected unsafe override void XOrICCore(
            ReadOnlySpan<byte> key,
            in Nonce nonce,
            ReadOnlySpan<byte> input,
            uint ic,
            Span<byte> output)
        {
            Debug.Assert(key.Length == crypto_stream_chacha20_ietf_KEYBYTES);
            Debug.Assert(nonce.Size == crypto_stream_chacha20_ietf_NONCEBYTES);
            Debug.Assert(output.Length == input.Length);

            fixed (byte* c = output)
            fixed (byte* m = input)
            fixed (Nonce* n = &nonce)
            fixed (byte* k = key)
            {
                int error = crypto_stream_chacha20_ietf_xor_ic(
                    c,
                    m,
                    (ulong)input.Length,
                    n,
                    ic,
                    k);

                Debug.Assert(error == 0);
            }
        }

        internal override bool TryExportKey(
            ReadOnlySpan<byte> key,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            return format switch
            {
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryExport(key, blob, out blobSize),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte>? owner,
            out PublicKey? publicKey)
        {
            publicKey = null;

            return format switch
            {
                KeyBlobFormat.RawSymmetricKey => RawKeyFormatter.TryImport(KeySize, blob, memoryPool, out memory, out owner),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
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
