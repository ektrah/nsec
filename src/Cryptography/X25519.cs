using System;
using System.Diagnostics;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  Curve25519
    //
    //      Elliptic Curve Diffie-Hellman (ECDH) based on the X25519 function
    //
    //  References:
    //
    //      RFC 7748 - Elliptic Curves for Security
    //
    //      draft-ietf-curdle-pkix-03 - Algorithm Identifiers for Ed25519,
    //          Ed25519ph, Ed448, Ed448ph, X25519 and X448 for use in the
    //          Internet X.509 Public Key Infrastructure
    //
    //  Parameters:
    //
    //      Private Key Size - 32 bytes.
    //
    //      Public Key Size - 32 bytes.
    //
    //      Shared Secret Size - 32 bytes.
    //
    public sealed class X25519 : KeyAgreementAlgorithm
    {
        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        private static readonly KeyFormatter s_nsecPrivateKeyFormatter =
            new X25519KeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[]
        {
            0x7F, 0x36, 0x41, crypto_scalarmult_curve25519_SCALARBYTES,
        });

        private static readonly PublicKeyFormatter s_nsecPublicKeyFormatter =
            new PublicKeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[]
        {
            0x7F, 0x37, 0x41, crypto_scalarmult_curve25519_SCALARBYTES,
        });

        private static readonly KeyFormatter s_pkixPrivateKeyFormatter =
            new X25519KeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[]
        {
            // +-- SEQUENCE (3 elements)
            //     +-- INTEGER 0
            //     +-- SEQUENCE (1 element)
            //     |   +-- OBJECT IDENTIFIER 1.3.101.110
            //     +-- OCTET STRING (1 element)
            //         +-- OCTET STRING (32 bytes)
            0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
            0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20,
        });

        private static readonly PublicKeyFormatter s_pkixPublicKeyFormatter =
            new PublicKeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[]
        {
            // +-- SEQUENCE (2 elements)
            //     +-- SEQUENCE (1 element)
            //     |   +-- OBJECT IDENTIFIER 1.3.101.110
            //     +-- BIT STRING (256 bits)
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
            0x6E, 0x03, 0x21, 0x00,
        });

        private static readonly KeyFormatter s_rawPrivateKeyFormatter =
            new X25519KeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[] { });

        private static readonly PublicKeyFormatter s_rawPublicKeyFormatter =
            new PublicKeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[] { });

        public X25519() : base(
            privateKeySize: crypto_scalarmult_curve25519_SCALARBYTES,
            publicKeySize: crypto_scalarmult_curve25519_SCALARBYTES,
            sharedSecretSize: crypto_scalarmult_curve25519_BYTES)
        {
            if (!s_selfTest.Value)
                throw new InvalidOperationException();
        }

        internal override void CreateKey(
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            publicKeyBytes = new byte[crypto_scalarmult_curve25519_SCALARBYTES];
            keyHandle = SecureMemoryHandle.Alloc(crypto_scalarmult_curve25519_SCALARBYTES);
            randombytes_buf(keyHandle, (IntPtr)keyHandle.Length);
            crypto_scalarmult_curve25519_base(publicKeyBytes, keyHandle);
        }

        internal override bool TryAgreeCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> otherPartyPublicKey,
            out SharedSecret result)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(otherPartyPublicKey.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            SecureMemoryHandle sharedSecretHandle = SecureMemoryHandle.Alloc(crypto_scalarmult_curve25519_BYTES);

            int error = crypto_scalarmult_curve25519(
                sharedSecretHandle,
                keyHandle,
                ref otherPartyPublicKey.DangerousGetPinnableReference());

            if (error != 0)
            {
                sharedSecretHandle.Dispose();
                result = null;
                return false;
            }

            result = new SharedSecret(sharedSecretHandle);
            return true;
        }

        internal override bool TryExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            out byte[] result)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPrivateKey:
                return s_rawPrivateKeyFormatter.TryExport(keyHandle, out result);
            case KeyBlobFormat.NSecPrivateKey:
                return s_nsecPrivateKeyFormatter.TryExport(keyHandle, out result);
            case KeyBlobFormat.PkixPrivateKey:
                return s_pkixPrivateKeyFormatter.TryExport(keyHandle, out result);
            case KeyBlobFormat.PkixPrivateKeyText:
                return s_pkixPrivateKeyFormatter.TryExportText(keyHandle, out result);
            default:
                result = null;
                return false;
            }
        }

        internal override bool TryExportPublicKey(
            ReadOnlySpan<byte> publicKeyBytes,
            KeyBlobFormat format,
            out byte[] result)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPublicKey:
                return s_rawPublicKeyFormatter.TryExport(publicKeyBytes, out result);
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.TryExport(publicKeyBytes, out result);
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.TryExport(publicKeyBytes, out result);
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.TryExportText(publicKeyBytes, out result);
            default:
                result = null;
                return false;
            }
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
                keyHandle = null;
                publicKeyBytes = null;
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

        private static bool SelfTest()
        {
            return (crypto_scalarmult_curve25519_bytes() == (IntPtr)crypto_scalarmult_curve25519_BYTES)
                && (crypto_scalarmult_curve25519_scalarbytes() == (IntPtr)crypto_scalarmult_curve25519_SCALARBYTES);
        }
    }
}
