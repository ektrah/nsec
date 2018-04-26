using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography.Buffers
{
    internal sealed class SecureMemoryManager<T> : MemoryManager<T>
        where T : /*unmanaged*/ struct
    {
        private readonly int _length;

        private IntPtr _ptr;

        public SecureMemoryManager(int length)
        {
            IntPtr ptr = sodium_malloc((UIntPtr)checked(length * Unsafe.SizeOf<T>()));

            if (ptr == IntPtr.Zero)
            {
                throw new OutOfMemoryException();
            }

            _length = length;
            _ptr = ptr;
        }

        ~SecureMemoryManager()
        {
            Dispose(false);
        }

        public override Memory<T> Memory => CreateMemory(_length);

        public unsafe override Span<T> GetSpan()
        {
            void* ptr = (void*)_ptr;

            if (ptr == null)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }

            return new Span<T>(ptr, _length);
        }

        public unsafe override MemoryHandle Pin(int elementIndex = 0)
        {
            void* ptr = (void*)_ptr;

            if (ptr == null)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }
            if (unchecked((uint)elementIndex > (uint)_length))
            {
                throw new ArgumentOutOfRangeException(nameof(elementIndex));
            }

            return new MemoryHandle(Unsafe.Add<T>(ptr, elementIndex), default, this);
        }

        public override void Unpin()
        {
        }

        protected override void Dispose(bool disposing)
        {
            sodium_free(Interlocked.Exchange(ref _ptr, IntPtr.Zero));
        }
    }
}
