using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_scalarmult_curve25519_SCALARBYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_curve25519_base(
            byte[] q,
            SecureMemoryHandle n);
    }
}
