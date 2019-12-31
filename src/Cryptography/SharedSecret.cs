using System;
using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;

namespace NSec.Cryptography
{
    [DebuggerDisplay("Size = {Size}")]
    public sealed class SharedSecret : IDisposable
    {
        private readonly IDisposable _disposable;
        private readonly ReadOnlyMemory<byte> _memory;

        private bool _disposed;

        internal SharedSecret(
            ReadOnlyMemory<byte> memory,
            IDisposable owner)
        {
            _memory = memory;
            _disposable = owner;
        }

        public int Size => _memory.Length;

        internal ReadOnlySpan<byte> Span
        {
            get
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(typeof(SharedSecret).FullName);
                }

                return _memory.Span;
            }
        }

        public static SharedSecret Import(
            ReadOnlySpan<byte> sharedSecret,
            in SharedSecretCreationParameters creationParameters = default)
        {
            if (sharedSecret.Length > 128)
            {
                throw Error.Argument_SharedSecretLength(nameof(sharedSecret), 128);
            }

            Sodium.Initialize();

            ReadOnlyMemory<byte> memory = default;
            IMemoryOwner<byte>? owner = default;
            bool success = false;

            try
            {
                ImportCore(sharedSecret, creationParameters.GetMemoryPool(), out memory, out owner);
                success = true;
            }
            finally
            {
                if (!success && owner != null)
                {
                    owner.Dispose();
                }
            }

            return new SharedSecret(memory, owner);
        }

        public void Dispose()
        {
            _disposed = true;
            _disposable.Dispose();
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string? ToString()
        {
            return typeof(SharedSecret).ToString();
        }

        private static void ImportCore(
            ReadOnlySpan<byte> sharedSecret,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner)
        {
            owner = memoryPool.Rent(sharedSecret.Length);
            memory = owner.Memory.Slice(0, sharedSecret.Length);
            sharedSecret.CopyTo(owner.Memory.Span);
        }
    }
}
