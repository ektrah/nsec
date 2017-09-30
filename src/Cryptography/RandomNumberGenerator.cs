using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public abstract class RandomNumberGenerator
    {
        private static readonly Lazy<DefaultRandomNumberGenerator> s_default = new Lazy<DefaultRandomNumberGenerator>(isThreadSafe: true);

        internal RandomNumberGenerator()
        {
            Sodium.Initialize();
        }

        public static RandomNumberGenerator Default => s_default.Value;

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
    }
}
