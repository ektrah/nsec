using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_hash_sha256_BYTES = 32;

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha256(
            Span<byte> @out,
            ReadOnlySpan<byte> @in,
            ulong inlen);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_hash_sha256_bytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha256_final(
            ref crypto_hash_sha256_state state,
            Span<byte> @out);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha256_init(
            ref crypto_hash_sha256_state state);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_hash_sha256_statebytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha256_update(
            ref crypto_hash_sha256_state state,
            ReadOnlySpan<byte> @in,
            ulong inlen);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha256_update(
            ref crypto_hash_sha256_state state,
            in uint @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 104)]
        internal struct crypto_hash_sha256_state
        {
        }
    }
}
