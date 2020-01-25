using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int SODIUM_LIBRARY_VERSION_MAJOR = 10;
        internal const int SODIUM_LIBRARY_VERSION_MINOR = 3;
        internal const string SODIUM_VERSION_STRING = "1.0.18";

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_library_version_major();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_library_version_minor();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_version_string();
    }
}
