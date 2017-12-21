using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void MisuseHandler();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_init();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_set_misuse_handler(MisuseHandler handler);
    }
}
