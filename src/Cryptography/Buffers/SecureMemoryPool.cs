using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography.Buffers
{
    internal sealed class SecureMemoryPool<T> : MemoryPool<T>
        where T : unmanaged
    {
        public static new readonly SecureMemoryPool<T> Shared = new SecureMemoryPool<T>();

        public SecureMemoryPool()
        {
        }

        public override int MaxBufferSize => int.MaxValue / Unsafe.SizeOf<T>();

        public override IMemoryOwner<T> Rent(int minBufferSize = -1)
        {
            if (minBufferSize == -1)
            {
                minBufferSize = unchecked(1 + (4095 / Unsafe.SizeOf<T>()));
            }
            else if (unchecked((uint)minBufferSize > (uint)(int.MaxValue / Unsafe.SizeOf<T>())))
            {
                throw new ArgumentOutOfRangeException(nameof(minBufferSize));
            }

            return new SecureMemoryManager<T>(minBufferSize);
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
