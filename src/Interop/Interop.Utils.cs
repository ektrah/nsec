using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void sodium_free(
            IntPtr ptr);

        [LibraryImport(Libraries.Libsodium)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial SecureMemoryHandle sodium_malloc(
            nuint size);
    }
}
