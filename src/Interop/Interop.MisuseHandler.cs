using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void MisuseHandler();
    }
}
