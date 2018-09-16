using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using static Interop.Libsodium;

namespace NSec.Experimental.PasswordBased
{
    //
    //  PBKDF2
    //
    //  References
    //
    //      RFC 8018 - PKCS #5: Password-Based Cryptography Specification
    //          Version 2.1
    //
    //  Parameters
    //
    //      Password Size - Any length.
    //
    //      Salt Size - Any length.
    //
    //      Iteration Count (c) - A positive integer.
    //
    //      Output Size - A positive integer less than or equal to (2^32-1)*32.
    //
    public sealed class Pbkdf2HmacSha256 : PasswordBasedKeyDerivationAlgorithm
    {
        private readonly int _c;

        public Pbkdf2HmacSha256() : this(100000)
        {
        }

        internal /*public*/ Pbkdf2HmacSha256(int c) : base(
            saltSize: 8,
            maxCount: int.MaxValue)
        {
            if (c <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(c));
            }

            _c = c;
        }

        internal /*public*/ int C => _c;

        internal override unsafe bool TryDeriveBytesCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> bytes)
        {
            byte* t = stackalloc byte[crypto_auth_hmacsha256_BYTES];
            byte* u = stackalloc byte[crypto_auth_hmacsha256_BYTES];

            try
            {
                fixed (byte* key = password)
                fixed (byte* @in = salt)
                fixed (byte* @out = bytes)
                {
                    int offset = 0;
                    uint counter = 0;
                    int chunkSize;

                    while ((chunkSize = bytes.Length - offset) > 0)
                    {
                        counter++;

                        uint counterBigEndian = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(counter) : counter;

                        crypto_auth_hmacsha256_state state;
                        crypto_auth_hmacsha256_init(&state, key, (UIntPtr)password.Length);
                        crypto_auth_hmacsha256_update(&state, @in, (ulong)salt.Length);
                        crypto_auth_hmacsha256_update(&state, &counterBigEndian, sizeof(uint));
                        crypto_auth_hmacsha256_final(&state, u);

                        for (int j = 1; j < _c; j++)
                        {
                            crypto_auth_hmacsha256_init(&state, key, (UIntPtr)password.Length);
                            crypto_auth_hmacsha256_update(&state, u, crypto_auth_hmacsha256_BYTES);
                            crypto_auth_hmacsha256_final(&state, u);

                            for (int k = 0; k < crypto_auth_hmacsha256_BYTES / sizeof(uint); k++)
                            {
                                ((uint*)t)[k] ^= ((uint*)u)[k];
                            }
                        }

                        if (chunkSize > crypto_auth_hmacsha256_BYTES)
                        {
                            chunkSize = crypto_auth_hmacsha256_BYTES;
                        }

                        Unsafe.CopyBlockUnaligned(@out + offset, t, (uint)chunkSize);
                        offset += chunkSize;
                    }

                    return true;
                }
            }
            finally
            {
                Unsafe.InitBlockUnaligned(t, 0, crypto_auth_hmacsha256_BYTES);
                Unsafe.InitBlockUnaligned(u, 0, crypto_auth_hmacsha256_BYTES);
            }
        }
    }
}
