using System;

namespace NSec.Cryptography
{
    public sealed class Ed25519 : SignatureAlgorithm
    {
        public Ed25519() : base(
            privateKeySize: 0,
            publicKeySize: 0,
            signatureSize: 0)
        {
        }

        internal override void SignCore(
            Key key,
            ReadOnlySpan<byte> data,
            Span<byte> signature)
        {
            throw new NotImplementedException();
        }

        internal override bool TryVerifyCore(
            PublicKey publicKey,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            throw new NotImplementedException();
        }
    }
}
