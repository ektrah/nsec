using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_auth_hmacsha256_BYTES = 32;
        internal const int crypto_auth_hmacsha256_KEYBYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_auth_hmacsha256_bytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_final(
            ref crypto_auth_hmacsha256_state state,
            ref byte @out);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_init(
            out crypto_auth_hmacsha256_state state,
            SecureMemoryHandle key,
            UIntPtr keylen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_init(
            out crypto_auth_hmacsha256_state state,
            ref byte key,
            UIntPtr keylen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_auth_hmacsha256_keybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_auth_hmacsha256_statebytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_update(
            ref crypto_auth_hmacsha256_state state,
            ref byte @in,
            ulong inlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_update(
            ref crypto_auth_hmacsha256_state state,
            ref uint @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 208, Pack = 8)]
        internal struct crypto_auth_hmacsha256_state { }
    }
}
