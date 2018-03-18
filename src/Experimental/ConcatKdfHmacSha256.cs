using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using NSec.Cryptography;
using static Interop.Libsodium;

namespace NSec.Experimental
{
    //
    //  Concatenation Key Derivation Function
    //
    //      Single-step key derivation function based on HMAC-SHA-256
    //
    //  References
    //
    //      NIST Special Publication 800-56A, Revision 2, Section 5.8
    //
    //  Parameters
    //
    //      Salt Size - Any.
    //
    //      Shared Info Size - Any.
    //
    //      Output Size - The length of the keying data to be generated must be
    //          less than or equal to HashLen*(2^32-1).
    //
    public sealed class ConcatKdfHmacSha256 : KeyDerivationAlgorithm
    {
        public ConcatKdfHmacSha256() : base(
            supportsSalt: true,
            maxCount: int.MaxValue)
        {
        }

        private protected override void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Span<byte> temp = stackalloc byte[crypto_auth_hmacsha256_BYTES];
            try
            {
                int offset = 0;
                uint counter = 0;
                int chunkSize;

                while ((chunkSize = bytes.Length - offset) > 0)
                {
                    counter++;

                    uint counterBigEndian = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(counter) : counter;

                    crypto_auth_hmacsha256_init(out crypto_auth_hmacsha256_state state, in MemoryMarshal.GetReference(salt), (UIntPtr)salt.Length);
                    crypto_auth_hmacsha256_update(ref state, in counterBigEndian, sizeof(uint));
                    crypto_auth_hmacsha256_update(ref state, in MemoryMarshal.GetReference(inputKeyingMaterial), (ulong)inputKeyingMaterial.Length);
                    crypto_auth_hmacsha256_update(ref state, in MemoryMarshal.GetReference(info), (ulong)info.Length);
                    crypto_auth_hmacsha256_final(ref state, ref MemoryMarshal.GetReference(temp));

                    if (chunkSize > crypto_auth_hmacsha256_BYTES)
                    {
                        chunkSize = crypto_auth_hmacsha256_BYTES;
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
