using System;
using System.Diagnostics;
using System.Threading;
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
        private static Ed25519? s_Ed25519;

        private readonly int _privateKeySize;
        private readonly int _publicKeySize;
        private readonly int _signatureSize;

        private protected SignatureAlgorithm(
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

        public static Ed25519 Ed25519
        {
            get
            {
                Ed25519? instance = s_Ed25519;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Ed25519, new Ed25519(), null);
                    instance = s_Ed25519;
                }
                return instance;
            }
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
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));

            byte[] signature = new byte[_signatureSize];
            SignCore(key.Span, data, signature);
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
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            if (signature.Length != _signatureSize)
                throw Error.Argument_SignatureLength(nameof(signature), _signatureSize);

            SignCore(key.Span, data, signature);
        }

        public bool Verify(
            PublicKey publicKey,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            if (publicKey == null)
                throw Error.ArgumentNull_Key(nameof(publicKey));
            if (publicKey.Algorithm != this)
                throw Error.Argument_PublicKeyAlgorithmMismatch(nameof(publicKey), nameof(publicKey));

            return signature.Length == _signatureSize && VerifyCore(in publicKey.GetPinnableReference(), data, signature);
        }

        internal sealed override int GetKeySize()
        {
            return _privateKeySize;
        }

        internal sealed override int GetPublicKeySize()
        {
            return _publicKeySize;
        }

        internal abstract override int GetSeedSize();

        private protected abstract void SignCore(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> data,
            Span<byte> signature);

        private protected abstract bool VerifyCore(
            in PublicKeyBytes publicKeyBytes,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature);
    }
}
