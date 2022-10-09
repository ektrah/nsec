using System;
using NSec.Cryptography;

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

        public Pbkdf2HmacSha256(
            in Pbkdf2Parameters parameters) : base(
            saltSize: 8,
            maxCount: int.MaxValue)
        {
            int c = parameters.IterationCount;

            if (c <= 0)
            {
                throw Error.Argument_InvalidPbkdf2Parameters(nameof(parameters));
            }

            _c = c;
        }

        internal void GetParameters(
            out Pbkdf2Parameters parameters)
        {
            parameters.IterationCount = _c;
        }

        internal override unsafe bool TryDeriveBytesCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> bytes)
        {
#if NETSTANDARD2_0
            throw new PlatformNotSupportedException();
#else

            System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                bytes,
                _c,
                System.Security.Cryptography.HashAlgorithmName.SHA256);
#endif
            return true;
        }
    }
}
