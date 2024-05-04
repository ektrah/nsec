using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_aead_chacha20poly1305_ietf_ABYTES = 16;
        internal const int crypto_aead_chacha20poly1305_ietf_KEYBYTES = 32;
        internal const int crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12;
        internal const int crypto_aead_chacha20poly1305_ietf_NSECBYTES = 0;

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_aead_chacha20poly1305_ietf_abytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_aead_chacha20poly1305_ietf_decrypt(
            Span<byte> m,
            out ulong mlen_p,
            IntPtr nsec,
            ReadOnlySpan<byte> c,
            ulong clen,
            ReadOnlySpan<byte> ad,
            ulong adlen,
            ReadOnlySpan<byte> npub,
            SecureMemoryHandle k);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_aead_chacha20poly1305_ietf_encrypt(
            Span<byte> c,
            out ulong clen_p,
            ReadOnlySpan<byte> m,
            ulong mlen,
            ReadOnlySpan<byte> ad,
            ulong adlen,
            IntPtr nsec,
            ReadOnlySpan<byte> npub,
            SecureMemoryHandle k);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_aead_chacha20poly1305_ietf_keybytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_aead_chacha20poly1305_ietf_npubbytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_aead_chacha20poly1305_ietf_nsecbytes();
    }
}
