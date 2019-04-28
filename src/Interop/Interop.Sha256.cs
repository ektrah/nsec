using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_hash_sha256_BYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_hash_sha256(
            byte* @out,
            byte* @in,
            ulong inlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_hash_sha256_bytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_hash_sha256_final(
            crypto_hash_sha256_state* state,
            byte* @out);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_hash_sha256_init(
            crypto_hash_sha256_state* state);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_hash_sha256_statebytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_hash_sha256_update(
            crypto_hash_sha256_state* state,
            byte* @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 104)]
        internal struct crypto_hash_sha256_state
        {
        }
    }
}
