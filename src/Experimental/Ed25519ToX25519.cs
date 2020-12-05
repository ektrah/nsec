using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public static class Ed25519ToX25519
    {
        public unsafe static byte[] SignEd25519SecretToCurve25519(byte[] privateKey)
        {
            var xPrivateKey = new byte[32];

            fixed (byte* x25519_sk = xPrivateKey)
            fixed (byte* ed25519_sk = privateKey)
            {
                int error = crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_sk);
                Debug.Assert(error == 0);
            }

            return xPrivateKey;
        }
        public unsafe static byte[] SignEd25519PublicToCurve25519(byte[] publicKey)
        {
            var xPublicKey = new byte[32];

            fixed (byte* x25519_sk = xPublicKey)
            fixed (byte* ed25519_sk = publicKey)
            {
                int error = crypto_sign_ed25519_pk_to_curve25519(x25519_sk, ed25519_sk);
                Debug.Assert(error == 0);
            }

            return xPublicKey;
        }
    }
}
