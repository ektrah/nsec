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
        internal static extern int crypto_generichash_blake2b_final(
            ref crypto_generichash_blake2b_state state,
            ref byte @out,
            IntPtr outlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_blake2b_init(
            out crypto_generichash_blake2b_state state,
            IntPtr key,
            IntPtr keylen,
            IntPtr outlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_blake2b_init(
            out crypto_generichash_blake2b_state state,
            SecureMemoryHandle key,
            IntPtr keylen,
            IntPtr outlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_blake2b_update(
            ref crypto_generichash_blake2b_state state,
            ref byte @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 384, Pack = 8)]
        internal struct crypto_generichash_blake2b_state { }
    }
}
