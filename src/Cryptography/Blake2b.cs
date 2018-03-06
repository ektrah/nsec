using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  BLAKE2b (unkeyed)
    //
    //  References:
    //
    //      RFC 7693 - The BLAKE2 Cryptographic Hash and Message Authentication
    //          Code (MAC)
    //
    //  Parameters:
    //
    //      Input Size - Between 0 and 2^128-1 bytes. (A Span<byte> can only
    //          hold up to 2^31-1 bytes.)
    //
    //      Hash Size - Between 1 and 64 bytes. For 128 bits of security, the
    //          output length should not be less than 32 bytes (BLAKE2b-256).
    //
    public sealed class Blake2b : HashAlgorithm
    {
        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public Blake2b() : base(
            minHashSize: 32,
            defaultHashSize: crypto_generichash_blake2b_BYTES,
            maxHashSize: crypto_generichash_blake2b_BYTES_MAX)
        {
            if (!s_selfTest.Value)
            {
                throw Error.Cryptographic_InitializationFailed(9461.ToString("X"));
            }
        }

        private protected override void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            Debug.Assert(hash.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hash.Length <= crypto_generichash_blake2b_BYTES_MAX);

            Span<byte> buffer = stackalloc byte[63 + Unsafe.SizeOf<crypto_generichash_blake2b_state>()];
            ref crypto_generichash_blake2b_state state = ref AlignPinnedReference(ref MemoryMarshal.GetReference(buffer));

            crypto_generichash_blake2b_init(out state, IntPtr.Zero, UIntPtr.Zero, (UIntPtr)hash.Length);
            crypto_generichash_blake2b_update(ref state, in MemoryMarshal.GetReference(data), (ulong)data.Length);
            crypto_generichash_blake2b_final(ref state, ref MemoryMarshal.GetReference(hash), (UIntPtr)hash.Length);
        }

        private protected override bool TryVerifyCore(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash)
        {
            Debug.Assert(hash.Length >= crypto_generichash_blake2b_BYTES_MIN);
            Debug.Assert(hash.Length <= crypto_generichash_blake2b_BYTES_MAX);

            Span<byte> buffer = stackalloc byte[63 + Unsafe.SizeOf<crypto_generichash_blake2b_state>()];
            ref crypto_generichash_blake2b_state state = ref AlignPinnedReference(ref MemoryMarshal.GetReference(buffer));

            Span<byte> temp = stackalloc byte[hash.Length];

            crypto_generichash_blake2b_init(out state, IntPtr.Zero, UIntPtr.Zero, (UIntPtr)temp.Length);
            crypto_generichash_blake2b_update(ref state, in MemoryMarshal.GetReference(data), (ulong)data.Length);
            crypto_generichash_blake2b_final(ref state, ref MemoryMarshal.GetReference(temp), (UIntPtr)temp.Length);

            int result = sodium_memcmp(in MemoryMarshal.GetReference(temp), in MemoryMarshal.GetReference(hash), (UIntPtr)hash.Length);

            return result == 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe ref crypto_generichash_blake2b_state AlignPinnedReference(ref byte value)
        {
            return ref sizeof(byte*) == sizeof(uint)
                ? ref Unsafe.AsRef<crypto_generichash_blake2b_state>((void*)(((uint)Unsafe.AsPointer(ref value) + 63u) & ~63u))
                : ref Unsafe.AsRef<crypto_generichash_blake2b_state>((void*)(((ulong)Unsafe.AsPointer(ref value) + 63ul) & ~63ul));
        }

        private static bool SelfTest()
        {
            return (crypto_generichash_blake2b_bytes() == (UIntPtr)crypto_generichash_blake2b_BYTES)
                && (crypto_generichash_blake2b_bytes_max() == (UIntPtr)crypto_generichash_blake2b_BYTES_MAX)
                && (crypto_generichash_blake2b_bytes_min() == (UIntPtr)crypto_generichash_blake2b_BYTES_MIN)
                && (crypto_generichash_blake2b_statebytes() == (UIntPtr)Unsafe.SizeOf<crypto_generichash_blake2b_state>());
        }
    }
}
