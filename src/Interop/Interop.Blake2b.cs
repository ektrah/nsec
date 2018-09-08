using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_generichash_blake2b_BYTES = 32;
        internal const int crypto_generichash_blake2b_BYTES_MAX = 64;
        internal const int crypto_generichash_blake2b_BYTES_MIN = 16;
        internal const int crypto_generichash_blake2b_KEYBYTES = 32;
        internal const int crypto_generichash_blake2b_KEYBYTES_MAX = 64;
        internal const int crypto_generichash_blake2b_KEYBYTES_MIN = 16;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_generichash_blake2b(
            byte* @out,
            UIntPtr outlen,
            byte* @in,
            ulong inlen,
            byte* key,
            UIntPtr keylen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_generichash_blake2b_bytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_generichash_blake2b_bytes_max();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_generichash_blake2b_bytes_min();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_generichash_blake2b_final(
            crypto_generichash_blake2b_state* state,
            byte* @out,
            UIntPtr outlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_generichash_blake2b_init(
            crypto_generichash_blake2b_state* state,
            byte* key,
            UIntPtr keylen,
            UIntPtr outlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_generichash_blake2b_keybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_generichash_blake2b_keybytes_max();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_generichash_blake2b_keybytes_min();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_generichash_blake2b_statebytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_generichash_blake2b_update(
            crypto_generichash_blake2b_state* state,
            byte* @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 384)]
        internal struct crypto_generichash_blake2b_state
        {
        }
    }
}
