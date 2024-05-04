using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_hash_sha512_BYTES = 64;

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha512(
            Span<byte> @out,
            ReadOnlySpan<byte> @in,
            ulong inlen);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_hash_sha512_bytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha512_final(
            ref crypto_hash_sha512_state state,
            Span<byte> @out);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha512_init(
            ref crypto_hash_sha512_state state);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_hash_sha512_statebytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha512_update(
            ref crypto_hash_sha512_state state,
            ReadOnlySpan<byte> @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 208)]
        internal struct crypto_hash_sha512_state
        {
        }
    }
}
