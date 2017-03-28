using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_hash_sha512_BYTES = 64;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_hash_sha512_bytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_final(
            ref crypto_hash_sha512_state state,
            ref byte @out);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_init(
            out crypto_hash_sha512_state state);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_hash_sha512_statebytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_update(
            ref crypto_hash_sha512_state state,
            ref byte @in,
            ulong inlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_update(
            ref crypto_hash_sha512_state state,
            ref uint @in,
            ulong inlen);

        [StructLayout(LayoutKind.Explicit, Size = 208, Pack = 8)]
        internal struct crypto_hash_sha512_state { }
    }
}
