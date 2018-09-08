using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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

        private protected unsafe override void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            byte* temp = stackalloc byte[crypto_auth_hmacsha256_BYTES];

            try
            {
                fixed (byte* key = salt)
                fixed (byte* ikm = inputKeyingMaterial)
                fixed (byte* @in = info)
                fixed (byte* @out = bytes)
                {
                    int offset = 0;
                    uint counter = 0;
                    int chunkSize;

                    while ((chunkSize = bytes.Length - offset) > 0)
                    {
                        counter++;

                        uint counterBigEndian = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(counter) : counter;

                        crypto_auth_hmacsha256_state state;
                        crypto_auth_hmacsha256_init(&state, key, (UIntPtr)salt.Length);
                        crypto_auth_hmacsha256_update(&state, &counterBigEndian, sizeof(uint));
                        crypto_auth_hmacsha256_update(&state, ikm, (ulong)inputKeyingMaterial.Length);
                        crypto_auth_hmacsha256_update(&state, @in, (ulong)info.Length);
                        crypto_auth_hmacsha256_final(&state, temp);

                        if (chunkSize > crypto_auth_hmacsha256_BYTES)
                        {
                            chunkSize = crypto_auth_hmacsha256_BYTES;
                        }

                        Unsafe.CopyBlockUnaligned(@out + offset, temp, (uint)chunkSize);
                        offset += chunkSize;
                    }
                }
            }
            finally
            {
                Unsafe.InitBlockUnaligned(temp, 0, crypto_auth_hmacsha256_BYTES);
            }
        }
    }
}
