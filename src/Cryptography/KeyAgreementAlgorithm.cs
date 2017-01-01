using System;
using System.Diagnostics;

namespace NSec.Cryptography
{
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
                throw new ArgumentException();
            if (otherPartyPublicKey == null)
                throw new ArgumentNullException(nameof(otherPartyPublicKey));
            if (otherPartyPublicKey.Algorithm != this)
                throw new ArgumentException();

            if (!TryAgreeCore(key, otherPartyPublicKey, out SharedSecret result))
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
                throw new ArgumentException();
            if (otherPartyPublicKey == null)
                throw new ArgumentNullException(nameof(otherPartyPublicKey));
            if (otherPartyPublicKey.Algorithm != this)
                throw new ArgumentException();

            return TryAgreeCore(key, otherPartyPublicKey, out result);
        }

        internal abstract bool TryAgreeCore(
            Key key,
            PublicKey otherPartyPublicKey,
            out SharedSecret result);
    }
}
