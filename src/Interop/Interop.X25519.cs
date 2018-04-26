using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_scalarmult_curve25519_BYTES = 32;
        internal const int crypto_scalarmult_curve25519_SCALARBYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_curve25519(
            out byte q,
            in byte n,
            in PublicKeyBytes p);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_curve25519_base(
            out PublicKeyBytes q,
            in byte n);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_scalarmult_curve25519_bytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_scalarmult_curve25519_scalarbytes();
    }
}
