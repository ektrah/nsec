using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_aead_chacha20poly1305_ietf_ABYTES = 16;
        internal const int crypto_aead_chacha20poly1305_ietf_KEYBYTES = 32;
        internal const int crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12;
        internal const int crypto_aead_chacha20poly1305_ietf_NSECBYTES = 0;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_aead_chacha20poly1305_ietf_abytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_ietf_decrypt(
            ref byte m,
            out ulong mlen_p,
            IntPtr nsec,
            ref byte c,
            ulong clen,
            ref byte ad,
            ulong adlen,
            ref byte npub,
            SecureMemoryHandle k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_ietf_encrypt(
            ref byte c,
            out ulong clen_p,
            ref byte m,
            ulong mlen,
            ref byte ad,
            ulong adlen,
            IntPtr nsec,
            ref byte npub,
            SecureMemoryHandle k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_aead_chacha20poly1305_ietf_keybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_aead_chacha20poly1305_ietf_npubbytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_aead_chacha20poly1305_ietf_nsecbytes();
    }
}
