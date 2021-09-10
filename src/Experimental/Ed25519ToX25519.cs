using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public static class Ed25519ToX25519
    {
        public static Key ConvertPrivateKey(
            Key key,
            Algorithm algorithm,
            in KeyCreationParameters creationParameters = default)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            if (!(key.Algorithm is Ed25519))
            {
                throw new ArgumentException(); // TODO: exception message
            }
            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }
            if (!(algorithm is X25519))
            {
                throw new ArgumentException(); // TODO: exception message
            }

            SecureMemoryHandle? keyHandle = default;
            PublicKey? publicKey = default;
            bool success = false;

            try
            {
                Span<byte> seed = stackalloc byte[crypto_scalarmult_curve25519_BYTES];
                try
                {
                    unsafe
                    {
                        fixed (byte* buf = seed)
                        {
                            int error = crypto_sign_ed25519_sk_to_curve25519(buf, key.Handle);

                            if (error != 0)
                            {
                                throw Error.InvalidOperation_InternalError();
                            }
                        }
                    }

                    algorithm.CreateKey(seed, out keyHandle, out publicKey);
                    success = true;
                }
                finally
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(seed);
                }
            }
            finally
            {
                if (!success && keyHandle != null)
                {
                    keyHandle.Dispose();
                }
            }

            return new Key(algorithm, in creationParameters, keyHandle, publicKey);
        }

        public static PublicKey ConvertPublicKey(
            PublicKey publicKey,
            Algorithm algorithm)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (!(publicKey.Algorithm is Ed25519))
            {
                throw new ArgumentException(); // TODO: exception message
            }
            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }
            if (!(algorithm is X25519))
            {
                throw new ArgumentException(); // TODO: exception message
            }

            PublicKey newPublicKey = new PublicKey(algorithm);

            unsafe
            {
                fixed (PublicKeyBytes* curve25519_pk = newPublicKey)
                fixed (PublicKeyBytes* ed25519_pk = publicKey)
                {
                    int error = crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk);

                    if (error != 0)
                    {
                        throw Error.InvalidOperation_InternalError();
                    }
                }
            }

            return newPublicKey;
        }
    }
}
