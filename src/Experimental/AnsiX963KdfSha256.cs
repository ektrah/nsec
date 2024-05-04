using System;
using System.Buffers.Binary;
using System.Diagnostics;
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
            int offset = 0;
            uint counter = 0;
            int chunkSize;

            try
            {
                crypto_hash_sha256_state initialState;

                crypto_hash_sha256_init(
                    ref initialState);

                crypto_hash_sha256_update(
                    ref initialState,
                    inputKeyingMaterial,
                    (ulong)inputKeyingMaterial.Length);

                while ((chunkSize = Math.Min(bytes.Length - offset, crypto_hash_sha256_BYTES)) > 0)
                {
                    counter++;

                    uint counterBigEndian = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(counter) : counter;

                    crypto_hash_sha256_state state = initialState;

                    crypto_hash_sha256_update(
                        ref state,
                        in counterBigEndian,
                        sizeof(uint));

                    crypto_hash_sha256_update(
                        ref state,
                        info,
                        (ulong)info.Length);

                    crypto_hash_sha256_final(
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
