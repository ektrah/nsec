using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  Argon2id
    //
    //  References
    //
    //      Argon2: the memory-hard function for password hashing and other
    //          applications
    //
    //      RFC 9106 - Argon2 Memory-Hard Function for Password Hashing and
    //          Proof-of-Work Applications
    //
    //  Parameters
    //
    //      Password Size - Any length from 0 to 2^32-1 bytes. (A Span<byte> can
    //          hold only up to 2^31-1 bytes.)
    //
    //      Nonce Length - Any length from 8 to 2^32-1 bytes. A length of
    //          16 bytes is recommended for password hashing and the only value
    //          accepted by libsodium.
    //
    //      Degree of Parallelism (p) - Any integer value from 1 to 2**24-1.
    //          libsodium does not accept this parameter and always uses a
    //          default value of 1.
    //
    //      Memory Size (m) - Any integer number of kibibytes from 8*p to
    //          2^32-1. libsodium accepts this parameter as the 'memlimit'
    //          argument (in bytes rather than kibibytes).
    //
    //      Number of Passes (t) - Any integer number from 1 to 2^32-1.
    //          libsodium accepts this parameter as the 'opslimit' argument.
    //
    //      Tag Length (T) - Any integer number of bytes from 4 to 2^32-1.
    //          libsodium requires this parameter to be at least 16 bytes.
    //
    //  Recommended Parameters
    //
    //      RFC 9106, Section 4, suggests the following settings:
    //
    //      | Scenario                                 | Lanes | RAM   |
    //      | ---------------------------------------- | ----- | ------|
    //      | Backend server authentication            |     8 | 4 GiB |
    //      | Key derivation for hard-drive encryption |     4 | 6 GiB |
    //      | Frontend server authentication           |     4 | 1 GiB |
    //
    //      Additionally, RFC 9106, Section 4, recommends the following general
    //      parameter sets for practical use. Note, however, that libsodium does
    //      not support the recommended p=4 lanes.
    //
    //      | Recommendation | p | m             | t |
    //      | -------------- | - | ------------- | - |
    //      | First Option   | 4 | 2^21  (2 GiB) | 1 |
    //      | Second Option  | 4 | 2^16 (64 MiB) | 3 |
    //
    //      libsodium includes the following three parameter sets:
    //
    //      | Strength      | opslimit | memlimit              | p | m    | t |
    //      | ------------- | -------- | --------------------- | - | ---- | - |
    //      | "Interactive" | 2        | 2^26 bytes   (64 MiB) | 1 | 2^16 | 2 |
    //      | "Moderate"    | 3        | 2^28 bytes  (256 MiB) | 1 | 2^18 | 3 |
    //      | "Sensitive"   | 4        | 2^30 bytes (1024 MiB) | 1 | 2^20 | 4 |
    //
    public sealed class Argon2id : PasswordBasedKeyDerivationAlgorithm
    {
        private static int s_selfTest;

        private readonly nuint _memLimit;
        private readonly ulong _opsLimit;

        public Argon2id(
            in Argon2Parameters parameters) : base(
            saltSize: crypto_pwhash_argon2id_SALTBYTES,
            maxCount: int.MaxValue)
        {
            int p = parameters.DegreeOfParallelism;
            long m = parameters.MemorySize;
            long t = parameters.NumberOfPasses;

            // checks from libsodium/crypto_pwhash/argon2/pwhash_argon2id.c
            if (p != 1)
            {
                throw Error.Argument_InvalidArgon2Parameters(nameof(parameters));
            }
            if (m < crypto_pwhash_argon2id_MEMLIMIT_MIN / 1024 ||
                m > (IntPtr.Size == sizeof(long) ? 4398046510080 / 1024 : 2147483648 / 1024))
            {
                throw Error.Argument_InvalidArgon2Parameters(nameof(parameters));
            }
            if (t < crypto_pwhash_argon2id_OPSLIMIT_MIN ||
                t > crypto_pwhash_argon2id_OPSLIMIT_MAX)
            {
                throw Error.Argument_InvalidArgon2Parameters(nameof(parameters));
            }

            _memLimit = (nuint)(m * 1024);
            _opsLimit = (ulong)t;

            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal void GetParameters(
            out Argon2Parameters parameters)
        {
            parameters.DegreeOfParallelism = 1;
            parameters.MemorySize = (long)_memLimit / 1024;
            parameters.NumberOfPasses = (long)_opsLimit;
        }

        internal override unsafe bool TryDeriveBytesCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> bytes)
        {
            Debug.Assert(salt.Length == crypto_pwhash_argon2id_SALTBYTES);

            const int MinCount = crypto_pwhash_argon2id_BYTES_MIN;
            bool min = bytes.Length < MinCount;
            byte* temp = stackalloc byte[MinCount];

            try
            {
                fixed (byte* @in = password)
                fixed (byte* salt_ = salt)
                fixed (byte* @out = bytes)
                {
                    int error = crypto_pwhash_argon2id(
                        min ? temp : @out,
                        (ulong)(min ? MinCount : bytes.Length),
                        (sbyte*)@in,
                        (ulong)password.Length,
                        salt_,
                        _opsLimit,
                        _memLimit,
                        crypto_pwhash_argon2id_ALG_ARGON2ID13);

                    if (min)
                    {
                        Unsafe.CopyBlockUnaligned(@out, temp, (uint)bytes.Length);
                    }

                    return error == 0;
                }
            }
            finally
            {
                Unsafe.InitBlockUnaligned(temp, 0, MinCount);
            }
        }

        private static void SelfTest()
        {
            if ((crypto_pwhash_argon2id_alg_argon2id13() != crypto_pwhash_argon2id_ALG_ARGON2ID13) ||
                (crypto_pwhash_argon2id_bytes_max() != uint.MaxValue) ||
                (crypto_pwhash_argon2id_bytes_min() != crypto_pwhash_argon2id_BYTES_MIN) ||
                (crypto_pwhash_argon2id_memlimit_max() != (nuint)(IntPtr.Size == sizeof(long) ? 4398046510080 : 2147483648)) ||
                (crypto_pwhash_argon2id_memlimit_min() != crypto_pwhash_argon2id_MEMLIMIT_MIN) ||
                (crypto_pwhash_argon2id_opslimit_max() != crypto_pwhash_argon2id_OPSLIMIT_MAX) ||
                (crypto_pwhash_argon2id_opslimit_min() != crypto_pwhash_argon2id_OPSLIMIT_MIN) ||
                (crypto_pwhash_argon2id_saltbytes() != crypto_pwhash_argon2id_SALTBYTES))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
