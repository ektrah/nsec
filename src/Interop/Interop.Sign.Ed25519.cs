using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_sign_ed25519_BYTES = 64;
        internal const int crypto_sign_ed25519_PUBLICKEYBYTES = 32;
        internal const int crypto_sign_ed25519_SECRETKEYBYTES = (32 + 32);
        internal const int crypto_sign_ed25519_SEEDBYTES = 32;

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_sign_ed25519_bytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_detached(
            Span<byte> sig,
            out ulong siglen_p,
            ReadOnlySpan<byte> m,
            ulong mlen,
            SecureMemoryHandle sk);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_pk_to_curve25519(
            ref PublicKeyBytes curve25519_pk,
            ref readonly PublicKeyBytes ed25519_pk);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_sign_ed25519_publickeybytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_sign_ed25519_secretkeybytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_seed_keypair(
            ref PublicKeyBytes pk,
            SecureMemoryHandle sk,
            ReadOnlySpan<byte> seed);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_sign_ed25519_seedbytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_sk_to_curve25519(
            Span<byte> curve25519_sk,
            SecureMemoryHandle ed25519_sk);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_sk_to_seed(
            Span<byte> seed,
            SecureMemoryHandle sk);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_verify_detached(
            ReadOnlySpan<byte> sig,
            ReadOnlySpan<byte> m,
            ulong mlen,
            ref readonly PublicKeyBytes pk);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519ph_final_create(
            ref crypto_sign_ed25519ph_state state,
            Span<byte> sig,
            out ulong siglen_p,
            SecureMemoryHandle sk);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519ph_final_verify(
            ref crypto_sign_ed25519ph_state state,
            ReadOnlySpan<byte> sig,
            ref readonly PublicKeyBytes pk);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519ph_init(
            ref crypto_sign_ed25519ph_state state);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_sign_ed25519ph_statebytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519ph_update(
            ref crypto_sign_ed25519ph_state state,
            ReadOnlySpan<byte> m,
            ulong mlen);

        [StructLayout(LayoutKind.Explicit, Size = 208)]
        internal struct crypto_sign_ed25519ph_state
        {
        }
    }
}
