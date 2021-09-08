using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using NSec.Cryptography;
using static Interop.Libsodium;

namespace NSec.Experimental.PasswordBased
{
    //
    //  Argon2i
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
    //          libsodium accepts this parameter as the 'opslimit' argument and
    //          mandates a value of at least 3.
    //
    //      Tag Length (T) - Any integer number of bytes from 4 to 2^32-1.
    //          libsodium requires this parameter to be at least 16 bytes.
    //
    //  Recommended Parameters
    //
    //      RFC 9106, Section 4, recommends Argon2id rather than Argon2i.
    //
    //      libsodium includes the following three parameter sets:
    //
    //      | Strength      | opslimit | memlimit             | p | m    | t |
    //      | ------------- | -------- | -------------------- | - | ---- | - |
    //      | "Interactive" | 4        | 2^25 bytes  (32 MiB) | 1 | 2^15 | 4 |
    //      | "Moderate"    | 6        | 2^27 bytes (128 MiB) | 1 | 2^17 | 6 |
    //      | "Sensitive"   | 8        | 2^29 bytes (512 MiB) | 1 | 2^19 | 8 |
    //
    public sealed class Argon2i : PasswordBasedKeyDerivationAlgorithm
    {
        private static int s_selfTest;

        private readonly nuint _memLimit;
        private readonly ulong _opsLimit;

        public Argon2i(
            in Argon2Parameters parameters) : base(
            saltSize: crypto_pwhash_argon2i_SALTBYTES,
            maxCount: int.MaxValue)
        {
            int p = parameters.DegreeOfParallelism;
            long m = parameters.MemorySize;
            long t = parameters.NumberOfPasses;

            // checks from libsodium/crypto_pwhash/argon2/pwhash_argon2i.c
            if (p != 1)
            {
                throw new ArgumentException(); // TODO
            }
            if (m < crypto_pwhash_argon2i_MEMLIMIT_MIN / 1024 ||
                m > (IntPtr.Size == sizeof(long) ? 4398046510080 / 1024 : 2147483648 / 1024))
            {
                throw new ArgumentException(); // TODO
            }
            if (t < crypto_pwhash_argon2i_OPSLIMIT_MIN ||
                t > crypto_pwhash_argon2i_OPSLIMIT_MAX)
            {
                throw new ArgumentException(); // TODO
            }

            _memLimit = (nuint)(m * 1024);
            _opsLimit = (ulong)t;

            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal override unsafe bool TryDeriveBytesCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> bytes)
        {
            Debug.Assert(salt.Length == crypto_pwhash_argon2i_SALTBYTES);

            const int MinCount = crypto_pwhash_argon2i_BYTES_MIN;
            bool min = bytes.Length < MinCount;
            byte* temp = stackalloc byte[MinCount];

            try
            {
                fixed (byte* @in = password)
                fixed (byte* salt_ = salt)
                fixed (byte* @out = bytes)
                {
                    int error = crypto_pwhash_argon2i(
                        min ? temp : @out,
                        (ulong)(min ? MinCount : bytes.Length),
                        (sbyte*)@in,
                        (ulong)password.Length,
                        salt_,
                        _opsLimit,
                        _memLimit,
                        crypto_pwhash_argon2i_ALG_ARGON2I13);

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
            if ((crypto_pwhash_argon2i_alg_argon2i13() != crypto_pwhash_argon2i_ALG_ARGON2I13) ||
                (crypto_pwhash_argon2i_bytes_max() != uint.MaxValue) ||
                (crypto_pwhash_argon2i_bytes_min() != crypto_pwhash_argon2i_BYTES_MIN) ||
                (crypto_pwhash_argon2i_memlimit_max() != (nuint)(IntPtr.Size == sizeof(long) ? 4398046510080 : 2147483648)) ||
                (crypto_pwhash_argon2i_memlimit_min() != crypto_pwhash_argon2i_MEMLIMIT_MIN) ||
                (crypto_pwhash_argon2i_opslimit_max() != crypto_pwhash_argon2i_OPSLIMIT_MAX) ||
                (crypto_pwhash_argon2i_opslimit_min() != crypto_pwhash_argon2i_OPSLIMIT_MIN) ||
                (crypto_pwhash_argon2i_saltbytes() != crypto_pwhash_argon2i_SALTBYTES))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
