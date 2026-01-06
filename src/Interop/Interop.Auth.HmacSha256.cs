using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_auth_hmacsha256_BYTES = 32;
        internal const int crypto_auth_hmacsha256_KEYBYTES = 32;

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_auth_hmacsha256_bytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_auth_hmacsha256_final(
            ref crypto_auth_hmacsha256_state state,
            Span<byte> @out);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_auth_hmacsha256_init(
            ref crypto_auth_hmacsha256_state state,
            ReadOnlySpan<byte> key,
            nuint keylen);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_auth_hmacsha256_init(
            ref crypto_auth_hmacsha256_state state,
            SecureMemoryHandle key,
            nuint keylen);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_auth_hmacsha256_keybytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_auth_hmacsha256_statebytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_auth_hmacsha256_update(
            ref crypto_auth_hmacsha256_state state,
            ReadOnlySpan<byte> @in,
            ulong inlen);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_auth_hmacsha256_update(
            ref crypto_auth_hmacsha256_state state,
            ref readonly uint @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 208)]
        internal struct crypto_auth_hmacsha256_state
        {
        }
    }
}
