
using System.Runtime.InteropServices;
using System;

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
            NSec.Cryptography.Nonce* n,
            byte* k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_stream_chacha20_ietf_xor(
            byte* c,
            byte* m,
            ulong mlen,
            NSec.Cryptography.Nonce* n,
            byte* k);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_stream_chacha20_ietf_xor_ic(
            byte* c,
            byte* m,
            ulong mlen,
            NSec.Cryptography.Nonce* n,
            UIntPtr ic,
            byte* k
        );

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_stream_chacha20_ietf_keybytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_stream_chacha20_ietf_noncebytes();
    }
}
