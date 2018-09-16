using System;
using System.Runtime.CompilerServices;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Experimental.PasswordBased
{
    //
    //  scrypt
    //
    //  References
    //
    //      RFC 7914 - The scrypt Password-Based Key Derivation Function
    //
    //  Parameters
    //
    //      Password Size - Any length.
    //
    //      Salt Size - libsodium uses a length of 32 bytes.
    //
    //      Block Size (r) - libsodium does not accept this parameter and always
    //          uses a default value of 8.
    //
    //      CPU/Memory Cost (N) - Must be larger than 1, a power of 2, and less
    //          than 2^(128*r/8). libsodium computes this parameter from the
    //          'opslimit' and 'memlimit' arguments.
    //
    //      Parallelization (p) - A positive integer less than or equal to
    //          ((2^32-1)*32)/(128*r). libsodium computes this parameter from
    //          the 'opslimit' and 'memlimit' arguments.
    //
    //      Output Size - A positive integer less than or equal to (2^32-1)*32.
    //
    //  Parameter Presets
    //
    //      | Strength    | opslimit | memlimit              | N    | r | p |
    //      | ----------- | -------- | --------------------- | ---- | - | - |
    //      | Interactive | 2^19     | 2^24 bytes   (16 MiB) | 2^14 | 8 | 1 |
    //      | Moderate    | 2^22     | 2^27 bytes  (128 MiB) | 2^17 | 8 | 1 |
    //      | Sensitive   | 2^25     | 2^30 bytes (1024 MiB) | 2^20 | 8 | 1 |
    //
    public sealed class Scrypt : PasswordBasedKeyDerivationAlgorithm
    {
        private static int s_selfTest;

        private readonly ulong _n;
        private readonly uint _r;
        private readonly uint _p;

        public Scrypt() : this(1 << 17, 8, 1)
        {
        }

        internal /*public*/ unsafe Scrypt(long n, int r, int p) : base(
            saltSize: crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
            maxCount: int.MaxValue)
        {
            if (n <= 1 || n > uint.MaxValue || (n & (n - 1)) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(n));
            }
            if (r <= 0 || p <= 0 || (long)r * p >= 1 << 30)
            {
                throw new ArgumentOutOfRangeException(nameof(r));
            }
            if ((sizeof(byte*) == sizeof(uint) ? n > (int)(uint.MaxValue / 128) / r : n > (long)(ulong.MaxValue / 128) / r))
            {
                throw new ArgumentOutOfRangeException(nameof(n));
            }
            if ((sizeof(byte*) == sizeof(uint) ? r > (int)(uint.MaxValue / 128) / p : r > (long)(ulong.MaxValue / 128) / p) ||
                (sizeof(byte*) == sizeof(uint) ? r > (int)(uint.MaxValue / 256) : false))
            {
                throw new ArgumentOutOfRangeException(nameof(r));
            }

            _n = (ulong)n;
            _r = (uint)r;
            _p = (uint)p;

            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal /*public*/ long N => (long)_n;

        internal /*public*/ int R => (int)_r;

        internal /*public*/ int P => (int)_p;

        internal override unsafe bool TryDeriveBytesCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> bytes)
        {
            const int MinCount = crypto_pwhash_scryptsalsa208sha256_BYTES_MIN;
            bool min = bytes.Length < MinCount;
            byte* temp = stackalloc byte[MinCount];

            try
            {
                fixed (byte* @in = password)
                fixed (byte* salt_ = salt)
                fixed (byte* @out = bytes)
                {
                    int error = crypto_pwhash_scryptsalsa208sha256_ll(
                        @in,
                        (UIntPtr)password.Length,
                        salt_,
                        (UIntPtr)salt.Length,
                        _n,
                        _r,
                        _p,
                        min ? temp : @out,
                        (UIntPtr)(min ? MinCount : bytes.Length));

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
            return (crypto_pwhash_scryptsalsa208sha256_bytes_min() == (UIntPtr)crypto_pwhash_scryptsalsa208sha256_BYTES_MIN)
                && (crypto_pwhash_scryptsalsa208sha256_memlimit_min() == (UIntPtr)(sizeof(byte*) == sizeof(uint) ? uint.MaxValue : 0x1000000000))
                && (crypto_pwhash_scryptsalsa208sha256_memlimit_min() == (UIntPtr)crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN)
                && (crypto_pwhash_scryptsalsa208sha256_opslimit_max() == (UIntPtr)uint.MaxValue)
                && (crypto_pwhash_scryptsalsa208sha256_opslimit_min() == (UIntPtr)crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN)
                && (crypto_pwhash_scryptsalsa208sha256_saltbytes() == (UIntPtr)crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
        }
    }
}
