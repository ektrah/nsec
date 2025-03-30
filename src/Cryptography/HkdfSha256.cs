using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  HKDF-SHA-256
    //
    //      HMAC-based Key Derivation Function (HKDF) using HMAC-SHA-256
    //
    //  References:
    //
    //      RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function
    //          (HKDF)
    //
    //      RFC 6234 - US Secure Hash Algorithms (SHA and SHA-based HMAC and
    //          HKDF)
    //
    //  Parameters
    //
    //      Pseudorandom Key Size - The first stage of HKDF-SHA-256 takes the
    //          input keying material and extracts from it a pseudorandom key
    //          of HashLen=32 bytes. The second stage expands a pseudorandom
    //          key of _at least_ HashLen bytes to the desired length.
    //
    //      Salt Size - HKDF is defined to operate with and without random salt.
    //          Ideally, the salt value is a random string of the length
    //          HashLen.
    //
    //      Shared Info Size - Any.
    //
    //      Output Size - The length of the output key material must be less
    //          than or equal to 255*HashLen=8160 bytes.
    //
    public sealed class HkdfSha256 : KeyDerivationAlgorithm2
    {
        public HkdfSha256() : base(
            supportsSalt: true,
            maxCount: byte.MaxValue * crypto_auth_hmacsha256_BYTES,
            pseudorandomKeySize: crypto_auth_hmacsha256_BYTES)
        {
        }

        private protected override void DeriveBytesCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            Debug.Assert(!inputKeyingMaterial.IsEmpty);

            System.Security.Cryptography.HKDF.DeriveKey(
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                inputKeyingMaterial,
                bytes,
                salt,
                info);
        }

        private protected override void ExpandCore(
            ReadOnlySpan<byte> pseudorandomKey,
            ReadOnlySpan<byte> info,
            Span<byte> bytes)
        {
            System.Security.Cryptography.HKDF.Expand(
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                pseudorandomKey,
                bytes,
                info);
        }

        private protected override void ExtractCore(
            ReadOnlySpan<byte> inputKeyingMaterial,
            ReadOnlySpan<byte> salt,
            Span<byte> pseudorandomKey)
        {
            Debug.Assert(!inputKeyingMaterial.IsEmpty);

            System.Security.Cryptography.HKDF.Extract(
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                inputKeyingMaterial,
                salt,
                pseudorandomKey);
        }
    }
}
