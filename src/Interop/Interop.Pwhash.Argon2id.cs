using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_pwhash_argon2id_ALG_ARGON2ID13 = 2;
        internal const int crypto_pwhash_argon2id_BYTES_MIN = 16;
        internal const int crypto_pwhash_argon2id_MEMLIMIT_MIN = 8192;
        internal const long crypto_pwhash_argon2id_OPSLIMIT_MAX = 4294967295;
        internal const int crypto_pwhash_argon2id_OPSLIMIT_MIN = 1;
        internal const int crypto_pwhash_argon2id_SALTBYTES = 16;

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_pwhash_argon2id(
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
        internal static partial int crypto_pwhash_argon2id_alg_argon2id13();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2id_bytes_max();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2id_bytes_min();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2id_memlimit_max();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2id_memlimit_min();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2id_opslimit_max();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2id_opslimit_min();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_argon2id_saltbytes();
    }
}
