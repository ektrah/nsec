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
        private static readonly KeyFormatter s_nsecPrivateKeyFormatter =
            new X25519KeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[]
        {
            0x7F, 0x06, 0x4E, 0x41, 0x00, 0x00, 0x00, 0x20,
        });

        private static readonly PublicKeyFormatter s_nsecPublicKeyFormatter =
            new PublicKeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[]
        {
            0x7F, 0x07, 0x4E, 0x41, 0x00, 0x00, 0x00, 0x20,
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
        }

        internal override SecureMemoryHandle CreateKey(
            out PublicKey publicKey)
        {
            byte[] publicKeyBytes = new byte[crypto_scalarmult_curve25519_SCALARBYTES];
            SecureMemoryHandle handle = SecureMemoryHandle.Alloc(crypto_scalarmult_curve25519_SCALARBYTES);
            randombytes_buf(handle, (IntPtr)handle.Length);
            crypto_scalarmult_curve25519_base(publicKeyBytes, handle);
            publicKey = new PublicKey(this, publicKeyBytes);
            return handle;
        }

        internal override bool TryAgreeCore(
            Key key,
            PublicKey otherPartyPublicKey,
            out SharedSecret result)
        {
            Debug.Assert(key != null);
            Debug.Assert(key.Handle.Length == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(otherPartyPublicKey != null);
            Debug.Assert(otherPartyPublicKey.Algorithm == this);
            Debug.Assert(otherPartyPublicKey.Bytes.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            SecureMemoryHandle sharedSecretHandle = SecureMemoryHandle.Alloc(crypto_scalarmult_curve25519_BYTES);

            int error = crypto_scalarmult_curve25519(
                sharedSecretHandle,
                key.Handle,
                ref otherPartyPublicKey.Bytes.DangerousGetPinnableReference());

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
    }
}
