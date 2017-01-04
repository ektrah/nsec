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
    //      draft-irtf-cfrg-eddsa-08 - Edwards-curve Digital Signature Algorithm
    //          (EdDSA)
    //
    //      draft-ietf-curdle-pkix-03 - Algorithm Identifiers for Ed25519,
    //          Ed25519ph, Ed448, Ed448ph, X25519 and X448 for use in the
    //          Internet X.509 Public Key Infrastructure
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
        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        private static readonly KeyFormatter s_nsecPrivateKeyFormatter =
            new Ed25519KeyFormatter(crypto_sign_ed25519_SEEDBYTES, new byte[]
        {
            0x7F, 0x34, 0x42, crypto_sign_ed25519_SEEDBYTES,
        });

        private static readonly PublicKeyFormatter s_nsecPublicKeyFormatter =
            new PublicKeyFormatter(crypto_sign_ed25519_PUBLICKEYBYTES, new byte[]
        {
            0x7F, 0x35, 0x42, crypto_sign_ed25519_PUBLICKEYBYTES,
        });

        private static readonly KeyFormatter s_pkixPrivateKeyFormatter =
            new Ed25519KeyFormatter(crypto_sign_ed25519_SEEDBYTES, new byte[]
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

        private static readonly PublicKeyFormatter s_pkixPublicKeyFormatter =
            new PublicKeyFormatter(crypto_sign_ed25519_PUBLICKEYBYTES, new byte[]
        {
            // +-- SEQUENCE (2 elements)
            //     +-- SEQUENCE (1 element)
            //     |   +-- OBJECT IDENTIFIER 1.3.101.112
            //     +-- BIT STRING (256 bits)
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
            0x70, 0x03, 0x21, 0x00,
        });

        private static readonly KeyFormatter s_rawPrivateKeyFormatter =
            new Ed25519KeyFormatter(crypto_sign_ed25519_SEEDBYTES, new byte[] { });

        private static readonly PublicKeyFormatter s_rawPublicKeyFormatter =
            new PublicKeyFormatter(crypto_sign_ed25519_PUBLICKEYBYTES, new byte[] { });

        public Ed25519() : base(
            privateKeySize: crypto_sign_ed25519_SEEDBYTES,
            publicKeySize: crypto_sign_ed25519_PUBLICKEYBYTES,
            signatureSize: crypto_sign_ed25519_BYTES)
        {
            if (!s_selfTest.Value)
                throw new InvalidOperationException();
        }

        internal override SecureMemoryHandle CreateKey(
            out PublicKey publicKey)
        {
            byte[] publicKeyBytes = new byte[crypto_sign_ed25519_PUBLICKEYBYTES];
            SecureMemoryHandle handle = SecureMemoryHandle.Alloc(crypto_sign_ed25519_SECRETKEYBYTES);
            crypto_sign_ed25519_keypair(publicKeyBytes, handle);
            publicKey = new PublicKey(this, publicKeyBytes);
            return handle;
        }

        internal override void SignCore(
            Key key,
            ReadOnlySpan<byte> data,
            Span<byte> signature)
        {
            Debug.Assert(key != null);
            Debug.Assert(key.Handle.Length == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            crypto_sign_ed25519_detached(
                ref signature.DangerousGetPinnableReference(),
                out ulong signatureLength,
                ref data.DangerousGetPinnableReference(),
                (ulong)data.Length,
                key.Handle);

            Debug.Assert((ulong)signature.Length == signatureLength);
        }

        internal override bool TryExportKey(
            Key key,
            KeyBlobFormat format,
            out byte[] result)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPrivateKey:
                return s_rawPrivateKeyFormatter.TryExport(key, out result);
            case KeyBlobFormat.NSecPrivateKey:
                return s_nsecPrivateKeyFormatter.TryExport(key, out result);
            case KeyBlobFormat.PkixPrivateKey:
                return s_pkixPrivateKeyFormatter.TryExport(key, out result);
            case KeyBlobFormat.PkixPrivateKeyText:
                return s_pkixPrivateKeyFormatter.TryExportText(key, out result);
            case KeyBlobFormat.RawPublicKey:
                return s_rawPublicKeyFormatter.TryExport(key.PublicKey, out result);
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.TryExport(key.PublicKey, out result);
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.TryExport(key.PublicKey, out result);
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.TryExportText(key.PublicKey, out result);
            default:
                result = null;
                return false;
            }
        }

        internal override bool TryExportPublicKey(
            PublicKey publicKey,
            KeyBlobFormat format,
            out byte[] result)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPublicKey:
                return s_rawPublicKeyFormatter.TryExport(publicKey, out result);
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.TryExport(publicKey, out result);
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.TryExport(publicKey, out result);
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.TryExportText(publicKey, out result);
            default:
                result = null;
                return false;
            }
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            KeyFlags flags,
            out Key result)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPrivateKey:
                return s_rawPrivateKeyFormatter.TryImport(this, flags, blob, out result);
            case KeyBlobFormat.NSecPrivateKey:
                return s_nsecPrivateKeyFormatter.TryImport(this, flags, blob, out result);
            case KeyBlobFormat.PkixPrivateKey:
                return s_pkixPrivateKeyFormatter.TryImport(this, flags, blob, out result);
            case KeyBlobFormat.PkixPrivateKeyText:
                return s_pkixPrivateKeyFormatter.TryImportText(this, flags, blob, out result);
            default:
                result = null;
                return false;
            }
        }

        internal override bool TryImportPublicKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out PublicKey result)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPublicKey:
                return s_rawPublicKeyFormatter.TryImport(this, blob, out result);
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.TryImport(this, blob, out result);
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.TryImport(this, blob, out result);
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.TryImportText(this, blob, out result);
            default:
                result = null;
                return false;
            }
        }

        internal override bool TryVerifyCore(
            PublicKey publicKey,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            Debug.Assert(publicKey != null);
            Debug.Assert(publicKey.Algorithm == this);
            Debug.Assert(publicKey.Bytes.Length == crypto_sign_ed25519_PUBLICKEYBYTES);
            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            int error = crypto_sign_ed25519_verify_detached(
                ref signature.DangerousGetPinnableReference(),
                ref data.DangerousGetPinnableReference(),
                (ulong)data.Length,
                ref publicKey.Bytes.DangerousGetPinnableReference());

            return error == 0;
        }

        private static bool SelfTest()
        {
            return (crypto_sign_ed25519_bytes() == (IntPtr)crypto_sign_ed25519_BYTES)
                && (crypto_sign_ed25519_publickeybytes() == (IntPtr)crypto_sign_ed25519_PUBLICKEYBYTES)
                && (crypto_sign_ed25519_secretkeybytes() == (IntPtr)crypto_sign_ed25519_SECRETKEYBYTES)
                && (crypto_sign_ed25519_seedbytes() == (IntPtr)crypto_sign_ed25519_SEEDBYTES);
        }
    }
}
