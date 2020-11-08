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
        internal static unsafe extern int crypto_aead_chacha20poly1305_ietf_decrypt(
            byte* m,
            out ulong mlen_p,
            byte* nsec,
            byte* c,
            ulong clen,
            byte* ad,
            ulong adlen,
            NSec.Cryptography.Nonce* npub,
            SecureMemoryHandle k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_aead_chacha20poly1305_ietf_encrypt(
            byte* c,
            out ulong clen_p,
            byte* m,
            ulong mlen,
            byte* ad,
            ulong adlen,
            byte* nsec,
            NSec.Cryptography.Nonce* npub,
            SecureMemoryHandle k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_aead_chacha20poly1305_ietf_keybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_aead_chacha20poly1305_ietf_npubbytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_aead_chacha20poly1305_ietf_nsecbytes();
    }
}
