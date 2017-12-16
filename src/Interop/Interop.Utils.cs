using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_free(
            IntPtr ptr);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern SecureMemoryHandle sodium_malloc(
            UIntPtr size);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_memcmp(
            in byte b1_,
            in byte b2_,
            UIntPtr len);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_memzero(
            ref byte pnt,
            UIntPtr len);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_mprotect_readonly(
            SecureMemoryHandle ptr);
    }
}
