using System;
using System.Diagnostics;
using static Interop.Libsodium;

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
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (otherPartyPublicKey == null)
                throw Error.ArgumentNull_Key(nameof(otherPartyPublicKey));
            if (otherPartyPublicKey.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(otherPartyPublicKey), key.Algorithm.GetType().FullName, GetType().FullName);

            SecureMemoryHandle sharedSecretHandle = null;
            bool success = false;

            try
            {
                success = TryAgreeCore(key.Handle, otherPartyPublicKey.Bytes, out sharedSecretHandle);
            }
            finally
            {
                if (!success && sharedSecretHandle != null)
                {
                    sharedSecretHandle.Dispose();
                }
            }

            if (!success)
            {
                throw Error.Cryptographic_KeyAgreementFailed();
            }

            return new SharedSecret(sharedSecretHandle);
        }

        public bool TryAgree(
            Key key,
            PublicKey otherPartyPublicKey,
            out SharedSecret result)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (otherPartyPublicKey == null)
                throw Error.ArgumentNull_Key(nameof(otherPartyPublicKey));
            if (otherPartyPublicKey.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(otherPartyPublicKey), key.Algorithm.GetType().FullName, GetType().FullName);

            SecureMemoryHandle sharedSecretHandle = null;
            bool success = false;

            try
            {
                success = TryAgreeCore(key.Handle, otherPartyPublicKey.Bytes, out sharedSecretHandle);
            }
            finally
            {
                if (!success && sharedSecretHandle != null)
                {
                    sharedSecretHandle.Dispose();
                }
            }

            result = success ? new SharedSecret(sharedSecretHandle) : null;
            return success;
        }

        internal abstract bool TryAgreeCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> otherPartyPublicKey,
            out SecureMemoryHandle sharedSecretHandle);
    }
}
