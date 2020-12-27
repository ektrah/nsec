using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_sign_ed25519_pk_to_curve25519(
            byte* curve25519_pk,
            byte* ed25519_pk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_sign_ed25519_sk_to_curve25519(
            byte* curve25519_sk,
            byte* ed25519_sk);
    }
}
