using System;
using NSec.Cryptography;

namespace NSec.Experimental.PasswordBased
{
    //
    //  PBMAC1
    //
    //      Password-Based Message Authentication Scheme
    //
    //  References
    //
    //      RFC 8018 - PKCS #5: Password-Based Cryptography Specification
    //          Version 2.1
    //
    //  Parameters
    //
    //      PBMAC1 combines a password-based key derivation function with an
    //      message authentication algorithm. The parameters depend on the
    //      primitives combined.
    //
    public sealed class PasswordBasedMacScheme
    {
        private readonly PasswordBasedKeyDerivationAlgorithm _keyDerivationAlgorithm;
        private readonly MacAlgorithm _macAlgorithm;

        public PasswordBasedMacScheme(
            PasswordBasedKeyDerivationAlgorithm keyDerivationAlgorithm,
            MacAlgorithm macAlgorithm)
        {
            if (keyDerivationAlgorithm == null)
                throw new ArgumentNullException(nameof(keyDerivationAlgorithm));
            if (macAlgorithm == null)
                throw new ArgumentNullException(nameof(macAlgorithm));

            _keyDerivationAlgorithm = keyDerivationAlgorithm;
            _macAlgorithm = macAlgorithm;
        }

        public PasswordBasedKeyDerivationAlgorithm KeyDerivationAlgorithm => _keyDerivationAlgorithm;

        public MacAlgorithm MacAlgorithm => _macAlgorithm;

        public int MacSize => _macAlgorithm.MacSize;

        public int SaltSize => _keyDerivationAlgorithm.SaltSize;

        public byte[] Mac(
            string password,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> data)
        {
            using Key key = _keyDerivationAlgorithm.DeriveKey(password, salt, _macAlgorithm);
            return _macAlgorithm.Mac(key, data);
        }

        public void Mac(
            string password,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            using Key key = _keyDerivationAlgorithm.DeriveKey(password, salt, _macAlgorithm);
            _macAlgorithm.Mac(key, data, mac);
        }

        public bool TryVerify(
            string password,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            using Key key = _keyDerivationAlgorithm.DeriveKey(password, salt, _macAlgorithm);
            return _macAlgorithm.Verify(key, data, mac);
        }
    }
}
