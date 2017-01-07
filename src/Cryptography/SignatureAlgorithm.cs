using System;
using System.Diagnostics;

namespace NSec.Cryptography
{
    //
    //  A digital signature algorithm
    //
    public abstract class SignatureAlgorithm : Algorithm
    {
        private readonly int _privateKeySize;
        private readonly int _publicKeySize;
        private readonly int _signatureSize;

        internal SignatureAlgorithm(
            int privateKeySize,
            int publicKeySize,
            int signatureSize)
        {
            Debug.Assert(privateKeySize > 0);
            Debug.Assert(publicKeySize > 0);
            Debug.Assert(signatureSize > 0);

            _privateKeySize = privateKeySize;
            _publicKeySize = publicKeySize;
            _signatureSize = signatureSize;
        }

        public int PrivateKeySize => _privateKeySize;

        public int PublicKeySize => _publicKeySize;

        public int SignatureSize => _signatureSize;

        public byte[] Sign(
            Key key,
            ReadOnlySpan<byte> data)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));

            byte[] signature = new byte[_signatureSize];
            SignCore(key, data, signature);
            return signature;
        }

        public void Sign(
            Key key,
            ReadOnlySpan<byte> data,
            Span<byte> signature)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));
            if (signature.Length != _signatureSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(signature));

            SignCore(key, data, signature);
        }

        public bool TryVerify(
            PublicKey publicKey,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(publicKey));
            if (signature.Length != _signatureSize)
                return false;

            return TryVerifyCore(publicKey, data, signature);
        }

        public void Verify(
            PublicKey publicKey,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(publicKey));
            if (signature.Length != _signatureSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(signature));

            if (!TryVerifyCore(publicKey, data, signature))
            {
                throw new CryptographicException();
            }
        }

        internal abstract void SignCore(
            Key key,
            ReadOnlySpan<byte> data,
            Span<byte> signature);

        internal abstract bool TryVerifyCore(
            PublicKey publicKey,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature);
    }
}
