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
        internal static unsafe extern int crypto_auth_hmacsha256_final(
            crypto_auth_hmacsha256_state* state,
            byte* @out);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_auth_hmacsha256_init(
            crypto_auth_hmacsha256_state* state,
            byte* key,
            UIntPtr keylen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_auth_hmacsha256_keybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_auth_hmacsha256_statebytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_auth_hmacsha256_update(
            crypto_auth_hmacsha256_state* state,
            byte* @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 208)]
        internal struct crypto_auth_hmacsha256_state
        {
        }
    }
}
