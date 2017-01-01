using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal sealed class SecureMemoryHandle : SafeHandle
        {
            private SecureMemoryHandle() : base(IntPtr.Zero, true)
            {
            }

            public override bool IsInvalid => (handle == IntPtr.Zero);

            public void MakeReadOnly()
            {
                sodium_mprotect_readonly(handle);
            }

            protected override bool ReleaseHandle()
            {
                sodium_free(handle);
                return true;
            }
        }
    }
}
