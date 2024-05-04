using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_stream_chacha20_ietf_KEYBYTES = 32;
        internal const int crypto_stream_chacha20_ietf_NONCEBYTES = 12;

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_stream_chacha20_ietf(
            Span<byte> c,
            ulong clen,
            ReadOnlySpan<byte> n,
            SecureMemoryHandle k);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_stream_chacha20_ietf_keybytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_stream_chacha20_ietf_noncebytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_stream_chacha20_ietf_xor(
            Span<byte> c,
            ReadOnlySpan<byte> m,
            ulong mlen,
            ReadOnlySpan<byte> n,
            SecureMemoryHandle k);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_stream_chacha20_ietf_xor_ic(
            Span<byte> c,
            ReadOnlySpan<byte> m,
            ulong mlen,
            ReadOnlySpan<byte> n,
            uint ic,
            SecureMemoryHandle k);
    }
}
