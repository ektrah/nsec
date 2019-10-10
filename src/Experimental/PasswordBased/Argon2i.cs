using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Experimental.PasswordBased
{
    //
    //  Argon2i
    //
    //  References
    //
    //      Argon2: the memory-hard function for password hashing and other
    //          applications <https://github.com/P-H-C/phc-winner-argon2/raw/
    //          master/argon2-specs.pdf>
    //
    //      draft-irtf-cfrg-argon2-08 - The memory-hard Argon2 password hash and
    //          proof-of-work function
    //
    //  Parameters
    //
    //      Password Size - Any length from 0 to 2^32-1 bytes.
    //
    //      Salt Size - Any length from 8 to 2^32-1 bytes. 16 bytes is
    //          recommended for password hashing and is the only value accepted
    //          by libsodium.
    //
    //      Degree of Parallelism (p) - Any integer value from 1 to 2**24-1.
    //          libsodium does not accept this parameter and always uses a
    //          default value of 1.
    //
    //      Memory Size (m) - Any integer number of kibibytes from 8*p to
    //          2^32-1. libsodium accepts this parameter as the 'memlimit'
    //          argument, which is in bytes rather than kibibytes however.
    //
    //      Number of Iterations (t) - Any integer number from 1 to 2^32-1.
    //          libsodium accepts this parameter as the 'opslimit' argument.
    //
    //      Tag Size - Any integer number of bytes from 4 to 2^32-1.
    //
    //  Parameter Presets
    //
    //      | Strength    | opslimit | memlimit             | p | m    | t |
    //      | ----------- | -------- | -------------------- | - | ---- | - |
    //      | Interactive | 4        | 2^25 bytes  (32 MiB) | 1 | 2^15 | 4 |
    //      | Moderate    | 6        | 2^27 bytes (128 MiB) | 1 | 2^17 | 6 |
    //      | Sensitive   | 8        | 2^29 bytes (512 MiB) | 1 | 2^19 | 8 |
    //
    public sealed class Argon2i : PasswordBasedKeyDerivationAlgorithm
    {
        private static int s_selfTest;

        private readonly UIntPtr _memLimit;
        private readonly ulong _opsLimit;

        public Argon2i() : this(1, 1 << 17, 6)
        {
        }

        internal /*public*/ unsafe Argon2i(int p, long m, int t) : base(
            saltSize: crypto_pwhash_argon2i_SALTBYTES,
            maxCount: int.MaxValue)
        {
            if (p != 1)
            {
                throw new ArgumentOutOfRangeException(nameof(p));
            }
            if (m < crypto_pwhash_argon2i_MEMLIMIT_MIN / 1024 ||
                m > (sizeof(byte*) == sizeof(uint) ? 0x200000 : uint.MaxValue))
            {
                throw new ArgumentOutOfRangeException(nameof(m));
            }
            if (t < crypto_pwhash_argon2i_OPSLIMIT_MIN)
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

        private static unsafe bool SelfTest()
        {
            return (crypto_pwhash_argon2i_alg_argon2i13() == crypto_pwhash_argon2i_ALG_ARGON2I13)
                && (crypto_pwhash_argon2i_bytes_min() == (UIntPtr)crypto_pwhash_argon2i_BYTES_MIN)
                && (crypto_pwhash_argon2i_memlimit_min() == (UIntPtr)(sizeof(byte*) == sizeof(uint) ? 0x200000 : uint.MaxValue))
                && (crypto_pwhash_argon2i_memlimit_min() == (UIntPtr)crypto_pwhash_argon2i_MEMLIMIT_MIN)
                && (crypto_pwhash_argon2i_opslimit_max() == (UIntPtr)uint.MaxValue)
                && (crypto_pwhash_argon2i_opslimit_min() == (UIntPtr)crypto_pwhash_argon2i_OPSLIMIT_MIN)
                && (crypto_pwhash_argon2i_saltbytes() == (UIntPtr)crypto_pwhash_argon2i_SALTBYTES);
        }
    }
}
