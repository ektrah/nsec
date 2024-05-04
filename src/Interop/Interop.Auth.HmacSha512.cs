using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_auth_hmacsha512_BYTES = 64;
        internal const int crypto_auth_hmacsha512_KEYBYTES = 32;

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_auth_hmacsha512_bytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_auth_hmacsha512_final(
            ref crypto_auth_hmacsha512_state state,
            Span<byte> @out);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_auth_hmacsha512_init(
            ref crypto_auth_hmacsha512_state state,
            ReadOnlySpan<byte> key,
            nuint keylen);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_auth_hmacsha512_init(
            ref crypto_auth_hmacsha512_state state,
            SecureMemoryHandle key,
            nuint keylen);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_auth_hmacsha512_keybytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_auth_hmacsha512_statebytes();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_auth_hmacsha512_update(
            ref crypto_auth_hmacsha512_state state,
            ReadOnlySpan<byte> @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 416)]
        internal struct crypto_auth_hmacsha512_state
        {
        }
    }
}
