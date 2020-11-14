using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_stream_chacha20_ietf_KEYBYTES = 32;
        internal const int crypto_stream_chacha20_ietf_NONCEBYTES = 12;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_stream_chacha20_ietf(
            byte* c,
            ulong clen,
            byte* n,
            SecureMemoryHandle k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint crypto_stream_chacha20_ietf_keybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nuint crypto_stream_chacha20_ietf_noncebytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_stream_chacha20_ietf_xor(
            byte* c,
            byte* m,
            ulong mlen,
            byte* n,
            SecureMemoryHandle k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_stream_chacha20_ietf_xor_ic(
            byte* c,
            byte* m,
            ulong mlen,
            byte* n,
            uint ic,
            SecureMemoryHandle k);
    }
}
