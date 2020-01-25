using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_pwhash_argon2i_ALG_ARGON2I13 = 1;
        internal const int crypto_pwhash_argon2i_BYTES_MIN = 16;
        internal const int crypto_pwhash_argon2i_MEMLIMIT_MIN = 8192;
        internal const int crypto_pwhash_argon2i_OPSLIMIT_MIN = 3;
        internal const int crypto_pwhash_argon2i_SALTBYTES = 16;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static unsafe extern int crypto_pwhash_argon2i(
            byte* @out,
            ulong outlen,
            sbyte* passwd,
            ulong passwdlen,
            byte* salt,
            ulong opslimit,
            UIntPtr memlimit,
            int alg);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_argon2i_alg_argon2i13();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_argon2i_bytes_max();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_argon2i_bytes_min();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_argon2i_memlimit_max();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_argon2i_memlimit_min();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_argon2i_opslimit_max();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_argon2i_opslimit_min();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_argon2i_saltbytes();
    }
}
