using System;
using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public abstract class RandomGenerator
    {
        private static RandomGenerator? s_Default;

        private protected RandomGenerator()
        {
            Sodium.Initialize();
        }

        public static RandomGenerator Default
        {
            get
            {
                RandomGenerator? instance = s_Default;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Default, new RandomGenerator.System(), null);
                    instance = s_Default;
                }
                return instance;
            }
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool Equals(
            object? objA,
            object? objB)
        {
            return object.Equals(objA, objB);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool ReferenceEquals(
            object? objA,
            object? objB)
        {
            return object.ReferenceEquals(objA, objB);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public sealed override bool Equals(
            object? obj)
        {
            return this == obj;
        }

        public byte[] GenerateBytes(
            int count)
        {
            if (count < 0)
            {
                throw Error.ArgumentOutOfRange_GenerateNegativeCount(nameof(count));
            }

            byte[] bytes = new byte[count];
            GenerateBytesCore(bytes);
            return bytes;
        }

        public void GenerateBytes(
            Span<byte> bytes)
        {
            GenerateBytesCore(bytes);
        }

        public int GenerateInt32()
        {
            return unchecked((int)(GenerateUInt32() & 0x7FFFFFFF));
        }

        public int GenerateInt32(
            int maxValue)
        {
            if (maxValue < 0)
            {
                throw Error.ArgumentOutOfRange_MustBePositive(nameof(maxValue), nameof(maxValue));
            }

            return unchecked((int)GenerateUInt32((uint)maxValue));
        }

        public int GenerateInt32(
            int minValue,
            int maxValue)
        {
            if (minValue > maxValue)
            {
                throw Error.Argument_MinMaxValue(nameof(minValue), nameof(minValue), nameof(maxValue));
            }

            return unchecked((int)((uint)minValue + GenerateUInt32((uint)maxValue - (uint)minValue)));
        }

        public Key GenerateKey(
            Algorithm algorithm,
            in KeyCreationParameters creationParameters = default)
        {
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            int seedSize = algorithm.GetSeedSize();
            Debug.Assert(seedSize <= 64);

            ReadOnlyMemory<byte> memory = default;
            IMemoryOwner<byte>? owner = default;
            PublicKey? publicKey = default;
            bool success = false;

            try
            {
                Span<byte> seed = stackalloc byte[seedSize];
                try
                {
                    GenerateBytesCore(seed);
                    algorithm.CreateKey(seed, creationParameters.GetMemoryPool(), out memory, out owner, out publicKey);
                    success = true;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(seed);
                }
            }
            finally
            {
                if (!success && owner != null)
                {
                    owner.Dispose();
                }
            }

            return new Key(algorithm, in creationParameters, memory, owner, publicKey);
        }

        public uint GenerateUInt32()
        {
            return GenerateUInt32Core();
        }

        public uint GenerateUInt32(
            uint maxValue)
        {
            if (maxValue < 2)
            {
                return 0;
            }

            uint min = unchecked((uint)-(int)maxValue) % maxValue;

            uint value;
            do
            {
                value = GenerateUInt32();
            }
            while (value < min);

            return value % maxValue;
        }

        public uint GenerateUInt32(
            uint minValue,
            uint maxValue)
        {
            if (minValue > maxValue)
            {
                throw Error.Argument_MinMaxValue(nameof(minValue), nameof(minValue), nameof(maxValue));
            }

            return unchecked(minValue + GenerateUInt32(maxValue - minValue));
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public sealed override int GetHashCode()
        {
            return RuntimeHelpers.GetHashCode(this);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public sealed override string? ToString()
        {
            return GetType().ToString();
        }

        private protected abstract void GenerateBytesCore(
            Span<byte> bytes);

        private protected abstract uint GenerateUInt32Core();

        internal sealed class System : RandomGenerator
        {
            private protected unsafe override void GenerateBytesCore(
                Span<byte> bytes)
            {
                fixed (byte* buf = bytes)
                {
                    randombytes_buf(buf, (UIntPtr)bytes.Length);
                }
            }

            private protected override uint GenerateUInt32Core()
            {
                randombytes_buf(out uint value, (UIntPtr)sizeof(uint));
                return value;
            }
        }
    }
}
