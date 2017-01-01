using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_hash_sha256_BYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_final(
            ref crypto_hash_sha256_state state,
            byte[] @out);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_final(
            ref crypto_hash_sha256_state state,
            SecureMemoryHandle @out);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_final(
            ref crypto_hash_sha256_state state,
            ref byte @out);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_init(
            out crypto_hash_sha256_state state);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha256_update(
            ref crypto_hash_sha256_state state,
            ref byte @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 104, Pack = 8)]
        internal struct crypto_hash_sha256_state { }
    }
}
