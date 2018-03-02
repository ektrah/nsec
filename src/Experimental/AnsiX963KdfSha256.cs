using System;
using static Interop.Libsodium;

namespace NSec.Cryptography.Experimental
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
            maxOutputSize: int.MaxValue)
        {
        }

        internal override void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Span<byte> temp;
            try
            {
                unsafe
                {
                    byte* pointer = stackalloc byte[crypto_hash_sha256_BYTES];
                    temp = new Span<byte>(pointer, crypto_hash_sha256_BYTES);
                }

                int offset = 0;
                uint counter = 0;
                int chunkSize;

                while ((chunkSize = bytes.Length - offset) > 0)
                {
                    counter++;

                    uint counterBigEndian = Utilities.ToBigEndian(counter);

                    crypto_hash_sha256_init(out crypto_hash_sha256_state state);
                    crypto_hash_sha256_update(ref state, ref inputKeyingMaterial.DangerousGetPinnableReference(), (ulong)inputKeyingMaterial.Length);
                    crypto_hash_sha256_update(ref state, ref counterBigEndian, sizeof(uint));
                    crypto_hash_sha256_update(ref state, ref info.DangerousGetPinnableReference(), (ulong)info.Length);
                    crypto_hash_sha256_final(ref state, ref temp.DangerousGetPinnableReference());

                    if (chunkSize > crypto_hash_sha256_BYTES)
                        chunkSize = crypto_hash_sha256_BYTES;
                    temp.Slice(0, chunkSize).CopyTo(bytes.Slice(offset));
                    offset += chunkSize;
                }
            }
            finally
            {
                sodium_memzero(ref temp.DangerousGetPinnableReference(), (UIntPtr)temp.Length);
            }
        }
    }
}
