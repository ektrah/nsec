using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_aead_aegis256_ABYTES = 32;
        internal const int crypto_aead_aegis256_KEYBYTES = 32;
        internal const int crypto_aead_aegis256_NPUBBYTES = 32;
        internal const int crypto_aead_aegis256_NSECBYTES = 0;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint crypto_aead_aegis256_abytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_aead_aegis256_decrypt(
            byte* m,
            out ulong mlen_p,
            byte* nsec,
            byte* c,
            ulong clen,
            byte* ad,
            ulong adlen,
            byte* npub,
            SecureMemoryHandle k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_aead_aegis256_encrypt(
            byte* c,
            out ulong clen_p,
            byte* m,
            ulong mlen,
            byte* ad,
            ulong adlen,
            byte* nsec,
            byte* npub,
            SecureMemoryHandle k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint crypto_aead_aegis256_keybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint crypto_aead_aegis256_npubbytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint crypto_aead_aegis256_nsecbytes();
    }
}
