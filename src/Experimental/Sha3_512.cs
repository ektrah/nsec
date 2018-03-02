using System;
using System.Runtime.InteropServices;
using static NSec.Cryptography.Experimental.Keccak.KeccakTiny;

namespace NSec.Cryptography.Experimental
{
    //
    //  SHA3-512
    //
    //      SHA-3 Permutation-Based Hash with a 512-bit message digest
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
    //      Hash Size - 64 bytes (256 bits of security).
    //
    public sealed class Sha3_512 : HashAlgorithm
    {
        public Sha3_512() : base(
            minHashSize: 32,
            defaultHashSize: 64,
            maxHashSize: 64)
        {
        }

        private protected override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            sha3_512(
                ref MemoryMarshal.GetReference(hash),
                (ulong)hash.Length,
                ref MemoryMarshal.GetReference(data),
                (ulong)data.Length);
        }

        private protected override bool TryVerifyCore(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash)
        {
            throw new NotImplementedException(); // TODO: Sha3_512.TryVerifyCore
        }
    }
}
