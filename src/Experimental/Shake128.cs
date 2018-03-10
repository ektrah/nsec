using System;
using System.Runtime.InteropServices;
using static NSec.Cryptography.Experimental.Keccak.KeccakTiny;

namespace NSec.Cryptography.Experimental
{
    //
    //  SHAKE128
    //
    //      SHA-3 Extendable-Output Function with 128-bit security strength
    //
    //  References:
    //
    //      FIPS 202 - SHA-3 Standard: Permutation-Based Hash and
    //          Extendable-Output Functions
    //
    //  Parameters:
    //
    //      Input Size - The SHA-3 functions are defined on messages of any bit
    //          length, including the empty string.
    //
    //      Hash Size - Any.
    //
    public sealed class Shake128 : HashAlgorithm
    {
        public Shake128() : base(
            hashSize: 32)
        {
        }

        private protected override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            shake128(
                ref MemoryMarshal.GetReference(hash),
                (ulong)hash.Length,
                ref MemoryMarshal.GetReference(data),
                (ulong)data.Length);
        }

        private protected override bool TryVerifyCore(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash)
        {
            throw new NotImplementedException(); // TODO: Shake128.TryVerifyCore
        }
    }
}
