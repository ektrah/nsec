using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using NSec.Cryptography;
using static Interop.Libsodium;

namespace NSec.Experimental.PasswordBased
{
    //
    //  Argon2id
    //
    //  References
    //
    //      Argon2: the memory-hard function for password hashing and other
    //          applications <https://github.com/P-H-C/phc-winner-argon2/raw/
    //          master/argon2-specs.pdf>
    //
    //      draft-irtf-cfrg-argon2-11 - The memory-hard Argon2 password hash and
    //          proof-of-work function
    //
    //  Parameters
    //
    //      Password Size - Any length from 0 to 2^32-1 bytes. (A Span<byte> can
    //          hold only up to 2^31-1 bytes.)
    //
    //      Salt Size - Any length from 8 to 2^32-1 bytes. A length of 16 bytes
    //          is recommended for password hashing and the only value accepted
    //          by libsodium.
    //
    //      Degree of Parallelism (p) - Any integer value from 1 to 2**24-1.
    //          libsodium does not accept this parameter and always uses a
    //          default value of 1.
    //
    //      Memory Size (m) - Any integer number of kibibytes from 8*p to
    //          2^32-1. libsodium accepts this parameter as the 'memlimit'
    //          argument (in bytes rather than kibibytes).
    //
    //      Number of Iterations (t) - Any integer number from 1 to 2^32-1.
    //          libsodium accepts this parameter as the 'opslimit' argument.
    //
    //      Tag Size - Any integer number of bytes from 4 to 2^32-1. libsodium
    //          requires this parameter to be at least 16 bytes.
    //
    //  Parameter Presets
    //
    //      | Strength    | opslimit | memlimit             | p | m    | t |
    //      | ----------- | -------- | -------------------- | - | ---- | - |
    //      | Interactive | 4        | 2^25 bytes  (32 MiB) | 1 | 2^15 | 4 |
    //      | Moderate    | 6        | 2^27 bytes (128 MiB) | 1 | 2^17 | 6 |
    //      | Sensitive   | 8        | 2^29 bytes (512 MiB) | 1 | 2^19 | 8 |
    //
    public sealed class Argon2id : PasswordBasedKeyDerivationAlgorithm
    {
        private static int s_selfTest;

        private readonly UIntPtr _memLimit;
        private readonly ulong _opsLimit;

        public Argon2id() : this(1, 1 << 17, 6)
        {
        }

        internal /*public*/ Argon2id(int p, long m, int t) : base(
            saltSize: crypto_pwhash_argon2id_SALTBYTES,
            maxCount: int.MaxValue)
        {
            // checks from libsodium/crypto_pwhash/argon2/pwhash_argon2id.c
            if (p != 1)
            {
                throw new ArgumentOutOfRangeException(nameof(p));
            }
            if (m < crypto_pwhash_argon2id_MEMLIMIT_MIN / 1024 ||
                m > (IntPtr.Size == sizeof(long) ? 4398046510080 / 1024 : 2147483648 / 1024))
            {
                throw new ArgumentOutOfRangeException(nameof(m));
            }
            if (t < crypto_pwhash_argon2id_OPSLIMIT_MIN)
            {
                throw new ArgumentOutOfRangeException(nameof(t));
            }

            _memLimit = (UIntPtr)(m * 1024);
            _opsLimit = (ulong)t;

            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal /*public*/ int P => 1;

        internal /*public*/ long M => (long)_memLimit / 1024;

        internal /*public*/ int T => (int)_opsLimit;

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
                (crypto_pwhash_argon2id_bytes_max() != (UIntPtr)uint.MaxValue) ||
                (crypto_pwhash_argon2id_bytes_min() != (UIntPtr)crypto_pwhash_argon2id_BYTES_MIN) ||
                (crypto_pwhash_argon2id_memlimit_max() != (UIntPtr)(IntPtr.Size == sizeof(long) ? 4398046510080 : 2147483648)) ||
                (crypto_pwhash_argon2id_memlimit_min() != (UIntPtr)crypto_pwhash_argon2id_MEMLIMIT_MIN) ||
                (crypto_pwhash_argon2id_opslimit_max() != (UIntPtr)uint.MaxValue) ||
                (crypto_pwhash_argon2id_opslimit_min() != (UIntPtr)crypto_pwhash_argon2id_OPSLIMIT_MIN) ||
                (crypto_pwhash_argon2id_saltbytes() != (UIntPtr)crypto_pwhash_argon2id_SALTBYTES))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
