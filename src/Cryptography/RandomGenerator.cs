using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public abstract class RandomGenerator
    {
        private static readonly Lazy<RandomGenerator.System> s_default = new Lazy<RandomGenerator.System>();

        private protected RandomGenerator()
        {
            Sodium.Initialize();
        }

        public static RandomGenerator Default => s_default.Value;

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
            KeyExportPolicies exportPolicy = KeyExportPolicies.None)
        {
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            int seedSize = algorithm.GetDefaultSeedSize();
            Debug.Assert(seedSize <= 64);

            SecureMemoryHandle keyHandle = null;
            byte[] publicKeyBytes = null;
            bool success = false;

            try
            {
                Span<byte> seed = stackalloc byte[seedSize];
                try
                {
                    GenerateBytesCore(seed);
                    algorithm.CreateKey(seed, out keyHandle, out publicKeyBytes);
                    success = true;
                }
                finally
                {
                    sodium_memzero(ref MemoryMarshal.GetReference(seed), (UIntPtr)seed.Length);
                }
            }
            finally
            {
                if (!success && keyHandle != null)
                {
                    keyHandle.Dispose();
                }
            }

            return new Key(algorithm, exportPolicy, keyHandle, publicKeyBytes);
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

            return minValue + GenerateUInt32(maxValue - minValue);
        }

        private protected abstract void GenerateBytesCore(
            Span<byte> bytes);

        private protected abstract uint GenerateUInt32Core();

        internal sealed class System : RandomGenerator
        {
            private protected override void GenerateBytesCore(
                Span<byte> bytes)
            {
                randombytes_buf(ref MemoryMarshal.GetReference(bytes), (UIntPtr)bytes.Length);
            }

            private protected override uint GenerateUInt32Core()
            {
                randombytes_buf(out uint value, (UIntPtr)sizeof(uint));
                return value;
            }
        }
    }
}
