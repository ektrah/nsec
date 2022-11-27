using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using NSec.Cryptography;
using static Interop.Libsodium;

namespace NSec.Experimental
{
    public abstract class RandomGenerator
    {
        private static RandomGenerator? s_Default;

        private protected RandomGenerator()
        {
            NSec.Cryptography.Sodium.Initialize();
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
            int upperExclusive)
        {
            if (upperExclusive < 0)
            {
                throw Error.ArgumentOutOfRange_MustBePositive(nameof(upperExclusive), nameof(upperExclusive));
            }

            return unchecked((int)GenerateUInt32((uint)upperExclusive));
        }

        public int GenerateInt32(
            int lowerInclusive,
            int upperExclusive)
        {
            if (lowerInclusive > upperExclusive)
            {
                throw Error.Argument_MinMaxValue(nameof(lowerInclusive), nameof(lowerInclusive), nameof(upperExclusive));
            }

            return unchecked((int)((uint)lowerInclusive + GenerateUInt32((uint)upperExclusive - (uint)lowerInclusive)));
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
            Debug.Assert(seedSize > 0 && seedSize <= 64);

            SecureMemoryHandle? keyHandle = default;
            PublicKey? publicKey = default;
            bool success = false;

            try
            {
                Span<byte> seed = stackalloc byte[seedSize];
                try
                {
                    GenerateBytesCore(seed);
                    algorithm.CreateKey(seed, out keyHandle, out publicKey);
                    success = true;
                }
                finally
                {
                    global::System.Security.Cryptography.CryptographicOperations.ZeroMemory(seed);
                }
            }
            finally
            {
                if (!success && keyHandle != null)
                {
                    keyHandle.Dispose();
                }
            }

            return new Key(algorithm, in creationParameters, keyHandle, publicKey);
        }

        public uint GenerateUInt32()
        {
            return GenerateUInt32Core();
        }

        public uint GenerateUInt32(
            uint upperExclusive)
        {
            if (upperExclusive < 2)
            {
                return 0;
            }

            uint min = unchecked((uint)-(int)upperExclusive) % upperExclusive;

            uint value;
            do
            {
                value = GenerateUInt32();
            }
            while (value < min);

            return value % upperExclusive;
        }

        public uint GenerateUInt32(
            uint lowerInclusive,
            uint upperExclusive)
        {
            if (lowerInclusive > upperExclusive)
            {
                throw Error.Argument_MinMaxValue(nameof(lowerInclusive), nameof(lowerInclusive), nameof(upperExclusive));
            }

            return unchecked(lowerInclusive + GenerateUInt32(upperExclusive - lowerInclusive));
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
                global::System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
            }

            private protected override uint GenerateUInt32Core()
            {
                Span<byte> bytes = stackalloc byte[sizeof(uint)];
                global::System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
                return global::System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes);
            }
        }
    }
}
