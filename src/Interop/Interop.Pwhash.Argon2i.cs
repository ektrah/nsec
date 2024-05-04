using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_pwhash_argon2i_ALG_ARGON2I13 = 1;
        internal const int crypto_pwhash_argon2i_BYTES_MIN = 16;
        internal const int crypto_pwhash_argon2i_MEMLIMIT_MIN = 8192;
        internal const long crypto_pwhash_argon2i_OPSLIMIT_MAX = 4294967295;
        internal const int crypto_pwhash_argon2i_OPSLIMIT_MIN = 3;
        internal const int crypto_pwhash_argon2i_SALTBYTES = 16;

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_pwhash_argon2i(
            Span<byte> @out,
            ulong outlen,
            ReadOnlySpan<sbyte> passwd,
            ulong passwdlen,
            ReadOnlySpan<byte> salt,
            ulong opslimit,
            nuint memlimit,
            int alg);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_pwhash_argon2i_alg_argon2i13();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2i_bytes_max();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2i_bytes_min();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2i_memlimit_max();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2i_memlimit_min();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2i_opslimit_max();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2i_opslimit_min();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2i_saltbytes();
    }
}
