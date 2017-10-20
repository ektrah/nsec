using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public abstract class RandomGenerator
    {
        private static readonly Lazy<RandomGenerator.System> s_default = new Lazy<RandomGenerator.System>(isThreadSafe: true);

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
                    sodium_memzero(ref seed.DangerousGetPinnableReference(), (UIntPtr)seed.Length);
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

        private protected abstract void GenerateBytesCore(
            Span<byte> bytes);

        internal sealed class System : RandomGenerator
        {
            private protected override void GenerateBytesCore(
                Span<byte> bytes)
            {
                randombytes_buf(ref bytes.DangerousGetPinnableReference(), (UIntPtr)bytes.Length);
            }
        }
    }
}
