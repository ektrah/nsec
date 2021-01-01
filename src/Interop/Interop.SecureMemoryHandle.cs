using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal sealed class SecureMemoryHandle : SafeHandle
        {
            private int _size;

            public SecureMemoryHandle() : base(IntPtr.Zero, true)
            {
            }

            public override bool IsInvalid => handle == IntPtr.Zero;

            public int Size => _size;

            public static SecureMemoryHandle Create(
                int size)
            {
                SecureMemoryHandle handle = sodium_malloc((nuint)size);

                if (handle.IsInvalid)
                {
                    throw new OutOfMemoryException();
                }

                handle._size = size;
                return handle;
            }

            public static SecureMemoryHandle CreateFrom(
                ReadOnlySpan<byte> source)
            {
                SecureMemoryHandle handle = Create(source.Length);

                bool mustCallRelease = false;
                try
                {
                    handle.DangerousAddRef(ref mustCallRelease);
                    source.CopyTo(handle.DangerousGetSpan());
                }
                finally
                {
                    if (mustCallRelease)
                    {
                        handle.DangerousRelease();
                    }
                }

                return handle;
            }

            public void CopyTo(
                Span<byte> destination)
            {
                bool mustCallRelease = false;
                try
                {
                    DangerousAddRef(ref mustCallRelease);
                    DangerousGetSpan().CopyTo(destination);
                }
                finally
                {
                    if (mustCallRelease)
                    {
                        DangerousRelease();
                    }
                }
            }

            public unsafe Span<byte> DangerousGetSpan()
            {
                return new Span<byte>((void*)handle, _size);
            }

            protected override bool ReleaseHandle()
            {
                sodium_free(handle);
                return true;
            }
        }
    }
}
