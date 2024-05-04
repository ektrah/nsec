using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_pwhash_scryptsalsa208sha256_BYTES_MIN = 16;
        internal const int crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN = 16777216;
        internal const long crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX = 4294967295;
        internal const int crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN = 32768;
        internal const int crypto_pwhash_scryptsalsa208sha256_SALTBYTES = 32;

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_scryptsalsa208sha256_bytes_max();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_scryptsalsa208sha256_bytes_min();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_pwhash_scryptsalsa208sha256_ll(
            ReadOnlySpan<byte> passwd,
            nuint passwdlen,
            ReadOnlySpan<byte> salt,
            nuint saltlen,
            ulong N,
            uint r,
            uint p,
            Span<byte> buf,
            nuint buflen);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_scryptsalsa208sha256_memlimit_max();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_scryptsalsa208sha256_memlimit_min();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_scryptsalsa208sha256_opslimit_max();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_scryptsalsa208sha256_opslimit_min();

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_pwhash_scryptsalsa208sha256_saltbytes();
    }
}
