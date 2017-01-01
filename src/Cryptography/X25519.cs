using System;

namespace NSec.Cryptography
{
    public sealed class X25519 : KeyAgreementAlgorithm
    {
        public X25519() : base(
            privateKeySize: 0,
            publicKeySize: 0,
            sharedSecretSize: 0)
        {
        }

        internal override bool TryAgreeCore(
            Key key,
            PublicKey otherPartyPublicKey,
            out SharedSecret result)
        {
            throw new NotImplementedException();
        }
    }
}
