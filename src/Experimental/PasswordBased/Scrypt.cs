using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using NSec.Cryptography;
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
    //          libsodium requires this parameter to be at least 16 bytes.
    //
    //  Recommended Parameters
    //
    //      The parameters N, r, and p should be tuned to match CPU power and
    //      memory capacity. RFC 7914, Section 2, mentions r=8 and p=1 as
    //      yielding good results at the time of writing (August 2016).
    //
    //      libsodium includes the following three parameter sets:
    //
    //      | Strength      | opslimit | memlimit              | N    | r | p |
    //      | ------------- | -------- | --------------------- | ---- | - | - |
    //      | "Interactive" | 2^19     | 2^24 bytes   (16 MiB) | 2^14 | 8 | 1 |
    //      | "Moderate"    | 2^22     | 2^27 bytes  (128 MiB) | 2^17 | 8 | 1 |
    //      | "Sensitive"   | 2^25     | 2^30 bytes (1024 MiB) | 2^20 | 8 | 1 |
    //
    public sealed class Scrypt : PasswordBasedKeyDerivationAlgorithm
    {
        private static int s_selfTest;

        private readonly ulong _n;
        private readonly uint _r;
        private readonly uint _p;

        internal /*public*/ Scrypt() : this(n: 1 << 17, r: 8, p: 1)
        {
        }

        internal /*public*/ Scrypt(long n, int r, int p) : base(
            saltSize: crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
            maxCount: int.MaxValue)
        {
            // checks from libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c
            if (n < 2 || n > uint.MaxValue || unchecked(n & (n - 1)) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(n));
            }
            if (r < 1 || p < 1 || (long)r * p >= 1 << 30)
            {
                throw new ArgumentOutOfRangeException(nameof(r));
            }
            if (IntPtr.Size == sizeof(long) ? n > (long)(ulong.MaxValue / 128) / r : n > (int)(uint.MaxValue / 128) / r)
            {
                throw new ArgumentOutOfRangeException(nameof(n));
            }
            if (IntPtr.Size == sizeof(long) ? r > (long)(ulong.MaxValue / 128) / p : r > (int)(uint.MaxValue / 128) / p || r > (int)(uint.MaxValue / 256))
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
            Debug.Assert(salt.Length == crypto_pwhash_scryptsalsa208sha256_SALTBYTES);

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
                        (nuint)password.Length,
                        salt_,
                        (nuint)salt.Length,
                        _n,
                        _r,
                        _p,
                        min ? temp : @out,
                        (nuint)(min ? MinCount : bytes.Length));

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
            if ((crypto_pwhash_scryptsalsa208sha256_bytes_max() != (nuint)(IntPtr.Size == sizeof(long) ? 0x1fffffffe0 : uint.MaxValue)) ||
                (crypto_pwhash_scryptsalsa208sha256_bytes_min() != crypto_pwhash_scryptsalsa208sha256_BYTES_MIN) ||
                (crypto_pwhash_scryptsalsa208sha256_memlimit_max() != (nuint)(IntPtr.Size == sizeof(long) ? 68719476736 : uint.MaxValue)) ||
                (crypto_pwhash_scryptsalsa208sha256_memlimit_min() != crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN) ||
                (crypto_pwhash_scryptsalsa208sha256_opslimit_max() != uint.MaxValue) ||
                (crypto_pwhash_scryptsalsa208sha256_opslimit_min() != crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN) ||
                (crypto_pwhash_scryptsalsa208sha256_saltbytes() != crypto_pwhash_scryptsalsa208sha256_SALTBYTES))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
