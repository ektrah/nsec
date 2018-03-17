using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_sign_ed25519_BYTES = 64;
        internal const int crypto_sign_ed25519_PUBLICKEYBYTES = 32;
        internal const int crypto_sign_ed25519_SECRETKEYBYTES = (32 + 32);
        internal const int crypto_sign_ed25519_SEEDBYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_sign_ed25519_bytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_detached(
            ref byte sig,
            out ulong siglen_p,
            in byte m,
            ulong mlen,
            SecureMemoryHandle sk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_sign_ed25519_publickeybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_sign_ed25519_secretkeybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_seed_keypair(
            out PublicKeyBytes pk,
            SecureMemoryHandle sk,
            in byte seed);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_sign_ed25519_seedbytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_seed(
            ref byte seed,
            SecureMemoryHandle sk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_verify_detached(
            in byte sig,
            in byte m,
            ulong mlen,
            in PublicKeyBytes pk);
    }
}
