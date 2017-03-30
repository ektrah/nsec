using System;
using System.Diagnostics;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  Ed25519
    //
    //      Digital Signature Algorithm (EdDSA) based on the edwards25519 curve
    //
    //  References:
    //
    //      RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)
    //
    //      draft-ietf-curdle-pkix-04 - Algorithm Identifiers for Ed25519,
    //          Ed448, X25519 and X448 for use in the Internet X.509 Public Key
    //          Infrastructure
    //
    //  Parameters:
    //
    //      Private Key Size - The private key is 32 bytes (256 bits). However,
    //          the libsodium representation of a private key is 64 bytes. We
    //          expose private keys as 32-byte byte strings and internally
    //          convert from/to the libsodium format as necessary.
    //
    //      Public Key Size - 32 bytes.
    //
    //      Signature Size - 64 bytes.
    //
    public sealed class Ed25519 : SignatureAlgorithm
    {
        private static readonly PrivateKeyFormatter s_nsecPrivateKeyFormatter = new Ed25519PrivateKeyFormatter(crypto_sign_ed25519_SEEDBYTES, new byte[]
        {
            0x7F, 0x00, 0x34, 0x42, crypto_sign_ed25519_SEEDBYTES, 0, 0, 0,
        });

        private static readonly PublicKeyFormatter s_nsecPublicKeyFormatter = new PublicKeyFormatter(crypto_sign_ed25519_PUBLICKEYBYTES, new byte[]
        {
            0x7F, 0x00, 0x35, 0x42, crypto_sign_ed25519_PUBLICKEYBYTES, 0, 0, 0,
        });

        private static readonly Oid s_oid = new Oid(1, 3, 101, 112);

        private static readonly PrivateKeyFormatter s_pkixPrivateKeyFormatter = new Ed25519PrivateKeyFormatter(crypto_sign_ed25519_SEEDBYTES, new byte[]
        {
            // +-- SEQUENCE (3 elements)
            //     +-- INTEGER 0
            //     +-- SEQUENCE (1 element)
            //     |   +-- OBJECT IDENTIFIER 1.3.101.112
            //     +-- OCTET STRING (1 element)
            //         +-- OCTET STRING (32 bytes)
            0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
            0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        });

        private static readonly PublicKeyFormatter s_pkixPublicKeyFormatter = new PublicKeyFormatter(crypto_sign_ed25519_PUBLICKEYBYTES, new byte[]
        {
            // +-- SEQUENCE (2 elements)
            //     +-- SEQUENCE (1 element)
            //     |   +-- OBJECT IDENTIFIER 1.3.101.112
            //     +-- BIT STRING (256 bits)
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
            0x70, 0x03, 0x21, 0x00,
        });

        private static readonly PrivateKeyFormatter s_rawPrivateKeyFormatter = new Ed25519PrivateKeyFormatter(crypto_sign_ed25519_SEEDBYTES, new byte[] { });

        private static readonly PublicKeyFormatter s_rawPublicKeyFormatter = new PublicKeyFormatter(crypto_sign_ed25519_PUBLICKEYBYTES, new byte[] { });

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public Ed25519() : base(
            privateKeySize: crypto_sign_ed25519_SEEDBYTES,
            publicKeySize: crypto_sign_ed25519_PUBLICKEYBYTES,
            signatureSize: crypto_sign_ed25519_BYTES)
        {
            if (!s_selfTest.Value)
                throw Error.Cryptographic_InitializationFailed();
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            Debug.Assert(seed.Length == crypto_sign_ed25519_SEEDBYTES);

            publicKeyBytes = new byte[crypto_sign_ed25519_PUBLICKEYBYTES];
            SecureMemoryHandle.Alloc(crypto_sign_ed25519_SECRETKEYBYTES, out keyHandle);
            crypto_sign_ed25519_seed_keypair(publicKeyBytes, keyHandle, ref seed.DangerousGetPinnableReference());
        }

        internal override byte[] ExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPrivateKey:
                return s_rawPrivateKeyFormatter.Export(keyHandle);
            case KeyBlobFormat.NSecPrivateKey:
                return s_nsecPrivateKeyFormatter.Export(keyHandle);
            case KeyBlobFormat.PkixPrivateKey:
                return s_pkixPrivateKeyFormatter.Export(keyHandle);
            case KeyBlobFormat.PkixPrivateKeyText:
                return s_pkixPrivateKeyFormatter.ExportText(keyHandle);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override byte[] ExportPublicKey(
            ReadOnlySpan<byte> publicKeyBytes,
            KeyBlobFormat format)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPublicKey:
                return s_rawPublicKeyFormatter.Export(publicKeyBytes);
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.Export(publicKeyBytes);
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.Export(publicKeyBytes);
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.ExportText(publicKeyBytes);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override int GetDefaultSeedSize()
        {
            return crypto_sign_ed25519_SEEDBYTES;
        }

        internal override void SignCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> signature)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            crypto_sign_ed25519_detached(
                ref signature.DangerousGetPinnableReference(),
                out ulong signatureLength,
                ref data.DangerousGetPinnableReference(),
                (ulong)data.Length,
                keyHandle);

            Debug.Assert((ulong)signature.Length == signatureLength);
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPrivateKey:
                return s_rawPrivateKeyFormatter.TryImport(blob, out keyHandle, out publicKeyBytes);
            case KeyBlobFormat.NSecPrivateKey:
                return s_nsecPrivateKeyFormatter.TryImport(blob, out keyHandle, out publicKeyBytes);
            case KeyBlobFormat.PkixPrivateKey:
                return s_pkixPrivateKeyFormatter.TryImport(blob, out keyHandle, out publicKeyBytes);
            case KeyBlobFormat.PkixPrivateKeyText:
                return s_pkixPrivateKeyFormatter.TryImportText(blob, out keyHandle, out publicKeyBytes);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryImportPublicKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out byte[] result)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPublicKey:
                return s_rawPublicKeyFormatter.TryImport(blob, out result);
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.TryImport(blob, out result);
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.TryImport(blob, out result);
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.TryImportText(blob, out result);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryVerifyCore(
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            Debug.Assert(publicKey.Length == crypto_sign_ed25519_PUBLICKEYBYTES);
            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            int error = crypto_sign_ed25519_verify_detached(
                ref signature.DangerousGetPinnableReference(),
                ref data.DangerousGetPinnableReference(),
                (ulong)data.Length,
                ref publicKey.DangerousGetPinnableReference());

            return error == 0;
        }

        private static bool SelfTest()
        {
            return (crypto_sign_ed25519_bytes() == (UIntPtr)crypto_sign_ed25519_BYTES)
                && (crypto_sign_ed25519_publickeybytes() == (UIntPtr)crypto_sign_ed25519_PUBLICKEYBYTES)
                && (crypto_sign_ed25519_secretkeybytes() == (UIntPtr)crypto_sign_ed25519_SECRETKEYBYTES)
                && (crypto_sign_ed25519_seedbytes() == (UIntPtr)crypto_sign_ed25519_SEEDBYTES);
        }
    }
}
