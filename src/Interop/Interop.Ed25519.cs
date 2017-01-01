using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_sign_ed25519_PUBLICKEYBYTES = 32;
        internal const int crypto_sign_ed25519_SECRETKEYBYTES = (32 + 32);
        internal const int crypto_sign_ed25519_SEEDBYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_seed_keypair(
            byte[] pk,
            SecureMemoryHandle sk,
            ref byte seed);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_seed(
            ref byte seed,
            SecureMemoryHandle sk);
    }
}
