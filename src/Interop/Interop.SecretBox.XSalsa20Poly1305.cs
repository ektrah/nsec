using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const string crypto_secretbox_PRIMITIVE = "xsalsa20poly1305";
        internal const int crypto_secretbox_xsalsa20poly1305_KEYBYTES = 32;
        internal const int crypto_secretbox_xsalsa20poly1305_MACBYTES = 16;
        internal const int crypto_secretbox_xsalsa20poly1305_NONCEBYTES = 24;

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_secretbox_easy(
            Span<byte> c,
            ReadOnlySpan<byte> m,
            ulong mlen,
            ReadOnlySpan<byte> n,
            SecureMemoryHandle k);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_secretbox_keybytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_secretbox_macbytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_secretbox_noncebytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_secretbox_open_easy(
            Span<byte> m,
            ReadOnlySpan<byte> c,
            ulong clen,
            ReadOnlySpan<byte> n,
            SecureMemoryHandle k);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial IntPtr crypto_secretbox_primitive();
    }
}
