using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_hash_sha512_BYTES = 64;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_hash_sha512(
            byte* @out,
            byte* @in,
            ulong inlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_hash_sha512_bytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_hash_sha512_final(
            crypto_hash_sha512_state* state,
            byte* @out);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_hash_sha512_init(
            crypto_hash_sha512_state* state);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_hash_sha512_statebytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_hash_sha512_update(
            crypto_hash_sha512_state* state,
            byte* @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 208)]
        internal struct crypto_hash_sha512_state
        {
        }
    }
}
