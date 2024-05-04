using System;
using System.Diagnostics;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
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

        public Scrypt(
            in ScryptParameters parameters) : base(
            saltSize: crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
            maxCount: int.MaxValue)
        {
            long n = parameters.Cost;
            int r = parameters.BlockSize;
            int p = parameters.Parallelization;

            // checks from libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c
            if (n < 2 || n > uint.MaxValue || unchecked(n & (n - 1)) != 0)
            {
                throw Error.Argument_InvalidScryptParameters(nameof(parameters));
            }
            if (r < 1 || p < 1 || (long)r * p >= 1 << 30)
            {
                throw Error.Argument_InvalidScryptParameters(nameof(parameters));
            }
            if (IntPtr.Size == sizeof(long) ? n > (long)(ulong.MaxValue / 128) / r : n > (int)(uint.MaxValue / 128) / r)
            {
                throw Error.Argument_InvalidScryptParameters(nameof(parameters));
            }
            if (IntPtr.Size == sizeof(long) ? r > (long)(ulong.MaxValue / 128) / p : r > (int)(uint.MaxValue / 128) / p || r > (int)(uint.MaxValue / 256))
            {
                throw Error.Argument_InvalidScryptParameters(nameof(parameters));
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

        internal void GetParameters(
            out ScryptParameters parameters)
        {
            parameters.Cost = (long)_n;
            parameters.BlockSize = (int)_r;
            parameters.Parallelization = (int)_p;
        }

        internal override bool TryDeriveBytesCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> bytes)
        {
            Debug.Assert(salt.Length == crypto_pwhash_scryptsalsa208sha256_SALTBYTES);

            const int MinCount = crypto_pwhash_scryptsalsa208sha256_BYTES_MIN;
            bool min = bytes.Length < MinCount;
            Span<byte> temp = stackalloc byte[MinCount];

            try
            {
                int error = crypto_pwhash_scryptsalsa208sha256_ll(
                    password,
                    (nuint)password.Length,
                    salt,
                    (nuint)salt.Length,
                    _n,
                    _r,
                    _p,
                    min ? temp : bytes,
                    (nuint)(min ? temp : bytes).Length);

                if (min)
                {
                    temp[..bytes.Length].CopyTo(bytes);
                }

                return error == 0;
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(temp);
            }
        }

        private static void SelfTest()
        {
            if ((crypto_pwhash_scryptsalsa208sha256_bytes_max() != (nuint)(IntPtr.Size == sizeof(long) ? 0x1fffffffe0 : uint.MaxValue)) ||
                (crypto_pwhash_scryptsalsa208sha256_bytes_min() != crypto_pwhash_scryptsalsa208sha256_BYTES_MIN) ||
                (crypto_pwhash_scryptsalsa208sha256_memlimit_max() != (nuint)(IntPtr.Size == sizeof(long) ? 68719476736 : uint.MaxValue)) ||
                (crypto_pwhash_scryptsalsa208sha256_memlimit_min() != crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN) ||
                (crypto_pwhash_scryptsalsa208sha256_opslimit_max() != crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX) ||
                (crypto_pwhash_scryptsalsa208sha256_opslimit_min() != crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN) ||
                (crypto_pwhash_scryptsalsa208sha256_saltbytes() != crypto_pwhash_scryptsalsa208sha256_SALTBYTES))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
