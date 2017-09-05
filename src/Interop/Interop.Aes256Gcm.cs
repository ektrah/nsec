using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_aead_aes256gcm_ABYTES = 16;
        internal const int crypto_aead_aes256gcm_KEYBYTES = 32;
        internal const int crypto_aead_aes256gcm_NPUBBYTES = 12;
        internal const int crypto_aead_aes256gcm_NSECBYTES = 0;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_aead_aes256gcm_abytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_decrypt(
            ref byte m,
            out ulong mlen_p,
            IntPtr nsec,
            ref byte c,
            ulong clen,
            ref byte ad,
            ulong adlen,
            ref NSec.Cryptography.Nonce npub,
            SecureMemoryHandle k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_encrypt(
            ref byte c,
            out ulong clen_p,
            ref byte m,
            ulong mlen,
            ref byte ad,
            ulong adlen,
            IntPtr nsec,
            ref NSec.Cryptography.Nonce npub,
            SecureMemoryHandle k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_is_available();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_aead_aes256gcm_keybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_aead_aes256gcm_npubbytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_aead_aes256gcm_nsecbytes();
    }
}
