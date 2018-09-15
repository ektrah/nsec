using System;
using System.Diagnostics;
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

        internal /*public*/ Scrypt(ulong n, uint r, uint p) : base(
            saltSize: crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
            maxCount: int.MaxValue)
        {
            _n = n;
            _r = r;
            _p = p;

            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal /*public*/ ulong N => _n;

        internal /*public*/ uint R => _r;

        internal /*public*/ uint P => _p;

        internal override unsafe bool TryDeriveBytesCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> bytes)
        {
            Debug.Assert(salt.Length == crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
            Debug.Assert(_r == 8);

            int error;

            if (bytes.Length >= crypto_pwhash_scryptsalsa208sha256_BYTES_MIN)
            {
                fixed (byte* @in = password)
                fixed (byte* salt_ = salt)
                fixed (byte* @out = bytes)
                {
                    error = crypto_pwhash_scryptsalsa208sha256_ll(
                        @in,
                        (UIntPtr)password.Length,
                        salt_,
                        (UIntPtr)salt.Length,
                        _n,
                        _r,
                        _p,
                        @out,
                        (UIntPtr)bytes.Length);
                }
            }
            else
            {
                byte* temp = stackalloc byte[crypto_pwhash_scryptsalsa208sha256_BYTES_MIN];

                try
                {
                    fixed (byte* @in = password)
                    fixed (byte* salt_ = salt)
                    {
                        error = crypto_pwhash_scryptsalsa208sha256_ll(
                            @in,
                            (UIntPtr)password.Length,
                            salt_,
                            (UIntPtr)salt.Length,
                            _n,
                            _r,
                            _p,
                            temp,
                            (UIntPtr)crypto_pwhash_scryptsalsa208sha256_BYTES_MIN);
                    }

                    fixed (byte* @out = bytes)
                    {
                        Unsafe.CopyBlockUnaligned(@out, temp, (uint)bytes.Length);
                    }
                }
                finally
                {
                    Unsafe.InitBlockUnaligned(temp, 0, crypto_pwhash_scryptsalsa208sha256_BYTES_MIN);
                }
            }

            return error == 0;
        }

        private static bool SelfTest()
        {
            return (crypto_pwhash_scryptsalsa208sha256_saltbytes() == (UIntPtr)crypto_pwhash_scryptsalsa208sha256_SALTBYTES)
                && (crypto_pwhash_scryptsalsa208sha256_bytes_min() == (UIntPtr)crypto_pwhash_scryptsalsa208sha256_BYTES_MIN);
        }
    }
}
