using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using NSec.Cryptography;
using static Interop.Libsodium;

namespace NSec.Experimental
{
    //
    //  ANSI X9.63 Key Derivation Function
    //
    //  References
    //
    //      SEC 1: Elliptic Curve Cryptography, Section 3.6.1
    //
    //  Parameters
    //
    //      Salt Size - No salt is used.
    //
    //      Shared Info Size - Any.
    //
    //      Output Size - The length of the keying data to be generated must be
    //          less than HashLen*(2^32-1).
    //
    public sealed class AnsiX963KdfSha256 : KeyDerivationAlgorithm
    {
        public AnsiX963KdfSha256() : base(
            supportsSalt: false,
            maxCount: int.MaxValue)
        {
        }

        private protected override void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Debug.Assert(salt.IsEmpty);

            Span<byte> temp = stackalloc byte[crypto_hash_sha256_BYTES];
            try
            {
                int offset = 0;
                uint counter = 0;
                int chunkSize;

                while ((chunkSize = bytes.Length - offset) > 0)
                {
                    counter++;

                    uint counterBigEndian = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(counter) : counter;

                    crypto_hash_sha256_init(out crypto_hash_sha256_state state);
                    crypto_hash_sha256_update(ref state, in MemoryMarshal.GetReference(inputKeyingMaterial), (ulong)inputKeyingMaterial.Length);
                    crypto_hash_sha256_update(ref state, in counterBigEndian, sizeof(uint));
                    crypto_hash_sha256_update(ref state, in MemoryMarshal.GetReference(info), (ulong)info.Length);
                    crypto_hash_sha256_final(ref state, ref MemoryMarshal.GetReference(temp));

                    if (chunkSize > crypto_hash_sha256_BYTES)
                    {
                        chunkSize = crypto_hash_sha256_BYTES;
                    }

                    temp.Slice(0, chunkSize).CopyTo(bytes.Slice(offset));
                    offset += chunkSize;
                }
            }
            finally
            {
                sodium_memzero(ref MemoryMarshal.GetReference(temp), (UIntPtr)temp.Length);
            }
        }
    }
}
