using System;

namespace NSec.Cryptography
{
    public class CryptographicException : Exception
    {
        public CryptographicException() { }

        public CryptographicException(string message) : base(message) { }

        public CryptographicException(string message, Exception innerException) : base(message, innerException) { }
    }
}
