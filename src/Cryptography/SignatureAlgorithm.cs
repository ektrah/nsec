using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  A digital signature algorithm
    //
    //  Examples
    //
    //      | Algorithm   | Reference  | Key Size | Signature Size |
    //      | ----------- | ---------- | -------- | -------------- |
    //      | ECDSA P-256 | FIPS 186-3 | 32       | 64             |
    //      | ECDSA P-521 | FIPS 186-3 | 66       | 132            |
    //      | Ed25519     | [1]        | 32       | 64             |
    //      | Ed448       | [1]        | 57       | 114            |
    //
    //      [1] draft-irtf-cfrg-eddsa-08
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
            SignCore(key.Handle, data, signature);
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

            SignCore(key.Handle, data, signature);
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

            return TryVerifyCore(publicKey.Bytes, data, signature);
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

            if (!TryVerifyCore(publicKey.Bytes, data, signature))
            {
                throw new CryptographicException();
            }
        }

        internal abstract void SignCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> signature);

        internal abstract bool TryVerifyCore(
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature);
    }
}
