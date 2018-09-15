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
    //      draft-irtf-cfrg-argon2-03 - The memory-hard Argon2 password hash and
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

        private readonly uint _p;
        private readonly uint _m;
        private readonly uint _t;

        public Argon2i() : this(1, 1 << 17, 6)
        {
        }

        internal /*public*/ Argon2i(uint p, uint m, uint t) : base(
            saltSize: crypto_pwhash_argon2i_SALTBYTES,
            maxCount: int.MaxValue)
        {
            _p = p;
            _m = m;
            _t = t;

            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal /*public*/ uint P => _p;

        internal /*public*/ uint M => _m;

        internal /*public*/ uint T => _t;

        internal override unsafe bool TryDeriveBytesCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> bytes)
        {
            Debug.Assert(salt.Length == crypto_pwhash_argon2i_SALTBYTES);
            Debug.Assert(_p == 1);

            int error;

            if (bytes.Length >= crypto_pwhash_argon2i_BYTES_MIN)
            {
                fixed (byte* @in = password)
                fixed (byte* salt_ = salt)
                fixed (byte* @out = bytes)
                {
                    error = crypto_pwhash_argon2i(
                        @out,
                        (ulong)bytes.Length,
                        (sbyte*)@in,
                        (ulong)password.Length,
                        salt_,
                        _t,
                        (UIntPtr)((ulong)_m * 1024),
                        crypto_pwhash_argon2i_ALG_ARGON2I13);
                }
            }
            else
            {
                byte* temp = stackalloc byte[crypto_pwhash_argon2i_BYTES_MIN];

                try
                {
                    fixed (byte* @in = password)
                    fixed (byte* salt_ = salt)
                    {
                        error = crypto_pwhash_argon2i(
                           temp,
                           crypto_pwhash_argon2i_BYTES_MIN,
                           (sbyte*)@in,
                           (ulong)password.Length,
                           salt_,
                           _t,
                           (UIntPtr)((ulong)_m * 1024),
                           crypto_pwhash_argon2i_ALG_ARGON2I13);
                    }

                    fixed (byte* @out = bytes)
                    {
                        Unsafe.CopyBlockUnaligned(@out, temp, (uint)bytes.Length);
                    }
                }
                finally
                {
                    Unsafe.InitBlockUnaligned(temp, 0, crypto_pwhash_argon2i_BYTES_MIN);
                }
            }

            return error == 0;
        }

        private static bool SelfTest()
        {
            return (crypto_pwhash_argon2i_alg_argon2i13() == crypto_pwhash_argon2i_ALG_ARGON2I13)
                && (crypto_pwhash_argon2i_saltbytes() == (UIntPtr)crypto_pwhash_argon2i_SALTBYTES)
                && (crypto_pwhash_argon2i_bytes_min() == (UIntPtr)crypto_pwhash_argon2i_BYTES_MIN);
        }
    }
}
