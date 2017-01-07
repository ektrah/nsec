using System;
using System.Diagnostics;

namespace NSec.Cryptography
{
    //
    //  A key agreement algorithm
    //
    //  Examples
    //
    //      | Algorithm  | Reference  | Key Size | Shared Secret Size |
    //      | ---------- | ---------- | -------- | ------------------ |
    //      | ECDH P-256 | FIPS 186-3 | 32       | 32                 |
    //      | ECDH P-521 | FIPS 186-3 | 66       | 66                 |
    //      | X25519     | RFC 7748   | 32       | 32                 |
    //      | X448       | RFC 7748   | 56       | 56                 |
    //
    public abstract class KeyAgreementAlgorithm : Algorithm
    {
        private readonly int _privateKeySize;
        private readonly int _publicKeySize;
        private readonly int _sharedSecretSize;

        internal KeyAgreementAlgorithm(
            int privateKeySize,
            int publicKeySize,
            int sharedSecretSize)
        {
            Debug.Assert(privateKeySize > 0);
            Debug.Assert(publicKeySize > 0);
            Debug.Assert(sharedSecretSize > 0);

            _privateKeySize = privateKeySize;
            _publicKeySize = publicKeySize;
            _sharedSecretSize = sharedSecretSize;
        }

        public int PrivateKeySize => _privateKeySize;

        public int PublicKeySize => _publicKeySize;

        public int SharedSecretSize => _sharedSecretSize;

        public SharedSecret Agree(
            Key key,
            PublicKey otherPartyPublicKey)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));
            if (otherPartyPublicKey == null)
                throw new ArgumentNullException(nameof(otherPartyPublicKey));
            if (otherPartyPublicKey.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(otherPartyPublicKey));

            if (!TryAgreeCore(key, otherPartyPublicKey.Bytes, out SharedSecret result))
            {
                throw new CryptographicException();
            }

            return result;
        }

        public bool TryAgree(
            Key key,
            PublicKey otherPartyPublicKey,
            out SharedSecret result)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(key));
            if (otherPartyPublicKey == null)
                throw new ArgumentNullException(nameof(otherPartyPublicKey));
            if (otherPartyPublicKey.Algorithm != this)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(otherPartyPublicKey));

            return TryAgreeCore(key, otherPartyPublicKey.Bytes, out result);
        }

        internal abstract bool TryAgreeCore(
            Key key,
            ReadOnlySpan<byte> otherPartyPublicKey,
            out SharedSecret result);
    }
}
