using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_hash_sha3256_BYTES = 32;
        internal const int crypto_hash_sha3512_BYTES = 64;

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha3256(
            Span<byte> @out,
            ReadOnlySpan<byte> @in,
            ulong inlen);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_hash_sha3256_bytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha3256_final(
            ref crypto_hash_sha3256_state state,
            Span<byte> @out);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha3256_init(
            ref crypto_hash_sha3256_state state);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_hash_sha3256_statebytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha3256_update(
            ref crypto_hash_sha3256_state state,
            ReadOnlySpan<byte> @in,
            ulong inlen);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha3512(
            Span<byte> @out,
            ReadOnlySpan<byte> @in,
            ulong inlen);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_hash_sha3512_bytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha3512_final(
            ref crypto_hash_sha3512_state state,
            Span<byte> @out);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha3512_init(
            ref crypto_hash_sha3512_state state);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_hash_sha3512_statebytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_hash_sha3512_update(
            ref crypto_hash_sha3512_state state,
            ReadOnlySpan<byte> @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 256)]
        internal struct crypto_hash_sha3256_state
        {
        }

        [StructLayout(LayoutKind.Explicit, Size = 256)]
        internal struct crypto_hash_sha3512_state
        {
        }
    }
}
