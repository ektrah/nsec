using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal sealed class SecureMemoryHandle : SafeHandle
        {
            private int _length;

            private SecureMemoryHandle() : base(IntPtr.Zero, true)
            {
            }

            public override bool IsInvalid => (handle == IntPtr.Zero);

            public int Length => _length;

            public static SecureMemoryHandle Alloc(int length)
            {
                Debug.Assert(length >= 0);

                SecureMemoryHandle handle = sodium_malloc((IntPtr)length);
                handle._length = length;
                return handle;
            }

            public unsafe Span<byte> DangerousGetSpan()
            {
                return new Span<byte>(handle.ToPointer(), _length);
            }

            public void Export(Span<byte> span)
            {
                bool addedRef = false;
                try
                {
                    DangerousAddRef(ref addedRef);
                    DangerousGetSpan().CopyTo(span);
                }
                finally
                {
                    if (addedRef)
                    {
                        DangerousRelease();
                    }
                }
            }

            public void Import(ReadOnlySpan<byte> span)
            {
                bool addedRef = false;
                try
                {
                    DangerousAddRef(ref addedRef);
                    span.CopyTo(DangerousGetSpan());
                }
                finally
                {
                    if (addedRef)
                    {
                        DangerousRelease();
                    }
                }
            }

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
