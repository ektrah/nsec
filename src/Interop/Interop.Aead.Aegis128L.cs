using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_aead_aegis128l_ABYTES = 32;
        internal const int crypto_aead_aegis128l_KEYBYTES = 16;
        internal const int crypto_aead_aegis128l_NPUBBYTES = 16;
        internal const int crypto_aead_aegis128l_NSECBYTES = 0;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint crypto_aead_aegis128l_abytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_aead_aegis128l_decrypt(
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
        internal static unsafe extern int crypto_aead_aegis128l_encrypt(
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
        internal static extern nuint crypto_aead_aegis128l_keybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint crypto_aead_aegis128l_npubbytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint crypto_aead_aegis128l_nsecbytes();
    }
}
