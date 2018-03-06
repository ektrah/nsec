using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_auth_hmacsha512_BYTES = 64;
        internal const int crypto_auth_hmacsha512_KEYBYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_auth_hmacsha512_bytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512_final(
            ref crypto_auth_hmacsha512_state state,
            ref byte @out);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512_init(
            out crypto_auth_hmacsha512_state state,
            in byte key,
            UIntPtr keylen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512_init(
            out crypto_auth_hmacsha512_state state,
            SecureMemoryHandle key,
            UIntPtr keylen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_auth_hmacsha512_keybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_auth_hmacsha512_statebytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512_update(
            ref crypto_auth_hmacsha512_state state,
            in byte @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 416)]
        internal struct crypto_auth_hmacsha512_state
        {
        }
    }
}
