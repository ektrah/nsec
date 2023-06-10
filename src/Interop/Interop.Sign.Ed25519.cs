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
        internal static extern nuint crypto_sign_ed25519_bytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_sign_ed25519_detached(
            byte* sig,
            out ulong siglen_p,
            byte* m,
            ulong mlen,
            SecureMemoryHandle sk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_sign_ed25519_pk_to_curve25519(
            PublicKeyBytes* curve25519_pk,
            PublicKeyBytes* ed25519_pk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint crypto_sign_ed25519_publickeybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint crypto_sign_ed25519_secretkeybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_sign_ed25519_seed_keypair(
            PublicKeyBytes* pk,
            SecureMemoryHandle sk,
            byte* seed);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint crypto_sign_ed25519_seedbytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_sign_ed25519_sk_to_curve25519(
            byte* curve25519_sk,
            SecureMemoryHandle ed25519_sk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_sign_ed25519_sk_to_seed(
            byte* seed,
            SecureMemoryHandle sk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_sign_ed25519_verify_detached(
            byte* sig,
            byte* m,
            ulong mlen,
            PublicKeyBytes* pk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_sign_ed25519ph_final_create(
            crypto_sign_ed25519ph_state* state,
            byte* sig,
            out ulong siglen_p,
            SecureMemoryHandle sk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_sign_ed25519ph_final_verify(
            crypto_sign_ed25519ph_state* state,
            byte* sig,
            PublicKeyBytes* pk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_sign_ed25519ph_init(
            crypto_sign_ed25519ph_state* state);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_sign_ed25519ph_update(
            crypto_sign_ed25519ph_state* state,
            byte* m,
            ulong mlen);

        [StructLayout(LayoutKind.Explicit, Size = 208)]
        internal struct crypto_sign_ed25519ph_state
        {
        }
    }
}
