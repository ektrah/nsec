using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_pwhash_scryptsalsa208sha256_BYTES_MIN = 16;
        internal const int crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN = 16777216;
        internal const int crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN = 32768;
        internal const int crypto_pwhash_scryptsalsa208sha256_SALTBYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_scryptsalsa208sha256_bytes_max();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_scryptsalsa208sha256_bytes_min();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_pwhash_scryptsalsa208sha256_ll(
            byte* passwd,
            UIntPtr passwdlen,
            byte* salt,
            UIntPtr saltlen,
            ulong N,
            uint r,
            uint p,
            byte* buf,
            UIntPtr buflen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_scryptsalsa208sha256_memlimit_max();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_scryptsalsa208sha256_memlimit_min();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_scryptsalsa208sha256_opslimit_max();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_scryptsalsa208sha256_opslimit_min();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_scryptsalsa208sha256_saltbytes();
    }
}
