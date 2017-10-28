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

            private SecureMemoryHandle() : base(
                invalidHandleValue: IntPtr.Zero,
                ownsHandle: true)
            {
            }

            public override bool IsInvalid => (handle == IntPtr.Zero);

            public int Length => _length;

            public static void Alloc(
                int length,
                out SecureMemoryHandle handle)
            {
                Debug.Assert(length >= 0);

                handle = sodium_malloc((UIntPtr)length);
                handle._length = length;
            }

            public static void Import(
                ReadOnlySpan<byte> span,
                out SecureMemoryHandle handle)
            {
                Alloc(span.Length, out handle);
                handle.Import(span);
            }

            public unsafe Span<byte> DangerousGetSpan()
            {
                return new Span<byte>(handle.ToPointer(), _length);
            }

            public int Export(
                Span<byte> span)
            {
                bool addedRef = false;
                try
                {
                    DangerousAddRef(ref addedRef);
                    DangerousGetSpan().CopyTo(span);
                    return _length;
                }
                finally
                {
                    if (addedRef)
                    {
                        DangerousRelease();
                    }
                }
            }

            public void Import(
                ReadOnlySpan<byte> span)
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
                sodium_mprotect_readonly(this);
            }

            protected override bool ReleaseHandle()
            {
                sodium_free(handle);
                return true;
            }
        }
    }
}
