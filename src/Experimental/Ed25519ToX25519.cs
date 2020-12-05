using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public static class Ed25519ToX25519
    {
        public unsafe static Key SignEd25519SecretToCurve25519(Key privateKey)
        {
            var xPrivateKey = new byte[32];

            fixed (byte* x25519_sk = xPrivateKey)
            fixed (byte* ed25519_sk = privateKey.Export(KeyBlobFormat.RawPrivateKey))
            {
                int error = crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_sk);
                Debug.Assert(error == 0);
            }

            return Key.Import(KeyAgreementAlgorithm.X25519, xPrivateKey, KeyBlobFormat.RawPrivateKey, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport});
        }
        public unsafe static PublicKey SignEd25519PublicToCurve25519(PublicKey publicKey)
        {
            var xPublicKey = new byte[32];

            fixed (byte* x25519_sk = xPublicKey)
            fixed (byte* ed25519_sk = publicKey.Export(KeyBlobFormat.RawPublicKey))
            {
                int error = crypto_sign_ed25519_pk_to_curve25519(x25519_sk, ed25519_sk);
                Debug.Assert(error == 0);
            }

            return PublicKey.Import(KeyAgreementAlgorithm.X25519, xPublicKey, KeyBlobFormat.RawPublicKey);
        }
    }
}
