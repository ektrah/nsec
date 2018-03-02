using System;
using System.Runtime.InteropServices;
using static NSec.Cryptography.Experimental.Keccak.KeccakTiny;

namespace NSec.Cryptography.Experimental
{
    //
    //  SHAKE256
    //
    //      SHA-3 Extendable-Output Function with 256-bit security strength
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
    public sealed class Shake256 : HashAlgorithm
    {
        public Shake256() : base(
            minHashSize: 0,
            defaultHashSize: 64,
            maxHashSize: int.MaxValue)
        {
        }

        private protected override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            shake256(
                ref MemoryMarshal.GetReference(hash),
                (ulong)hash.Length,
                ref MemoryMarshal.GetReference(data),
                (ulong)data.Length);
        }

        private protected override bool TryVerifyCore(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash)
        {
            throw new NotImplementedException(); // TODO: Shake256.TryVerifyCore
        }
    }
}
