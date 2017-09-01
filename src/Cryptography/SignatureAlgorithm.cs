using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  A digital signature algorithm
    //
    //  Candidates
    //
    //      | Algorithm   | Reference  | Key Size | Signature Size |
    //      | ----------- | ---------- | -------- | -------------- |
    //      | ECDSA P-256 | FIPS 186-3 | 32       | 64             |
    //      | ECDSA P-521 | FIPS 186-3 | 66       | 132            |
    //      | Ed25519     | RFC 8032   | 32       | 64             |
    //      | Ed448       | RFC 8032   | 57       | 114            |
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
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);

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
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (signature.Length != _signatureSize)
                throw Error.Argument_SignatureLength(nameof(signature), _signatureSize.ToString());

            SignCore(key.Handle, data, signature);
        }

        public bool TryVerify(
            PublicKey publicKey,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            if (publicKey == null)
                throw Error.ArgumentNull_Key(nameof(publicKey));
            if (publicKey.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(publicKey), publicKey.Algorithm.GetType().FullName, GetType().FullName);
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
                throw Error.ArgumentNull_Key(nameof(publicKey));
            if (publicKey.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(publicKey), publicKey.Algorithm.GetType().FullName, GetType().FullName);

            if ((signature.Length != _signatureSize) || !TryVerifyCore(publicKey.Bytes, data, signature))
            {
                throw Error.Cryptographic_VerificationFailed();
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
