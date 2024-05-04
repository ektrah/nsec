using System;
using System.Buffers.Binary;
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
            int offset = 0;
            uint counter = 0;
            int chunkSize;

            try
            {
                crypto_auth_hmacsha256_state initialState;

                crypto_auth_hmacsha256_init(
                    ref initialState,
                    salt,
                    (nuint)salt.Length);

                while ((chunkSize = Math.Min(bytes.Length - offset, crypto_auth_hmacsha256_BYTES)) > 0)
                {
                    counter++;

                    uint counterBigEndian = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(counter) : counter;

                    crypto_auth_hmacsha256_state state = initialState;

                    crypto_auth_hmacsha256_update(
                        ref state,
                        in counterBigEndian,
                        sizeof(uint));

                    crypto_auth_hmacsha256_update(
                        ref state,
                        inputKeyingMaterial,
                        (ulong)inputKeyingMaterial.Length);

                    crypto_auth_hmacsha256_update(
                        ref state,
                        info,
                        (ulong)info.Length);

                    crypto_auth_hmacsha256_final(
                        ref state,
                        temp);

                    temp[..chunkSize].CopyTo(bytes[offset..]);
                    offset += chunkSize;
                }
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(temp);
            }
        }
    }
}
