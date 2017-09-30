using System;
using System.Diagnostics;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  X25519
    //
    //      Elliptic Curve Diffie-Hellman (ECDH) based on the curve25519 curve
    //
    //  References:
    //
    //      RFC 7748 - Elliptic Curves for Security
    //
    //      RFC 5958 - Asymmetric Key Packages
    //
    //      draft-ietf-curdle-pkix-06 - Algorithm Identifiers for Ed25519,
    //          Ed448, X25519 and X448 for use in the Internet X.509 Public Key
    //          Infrastructure
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
        private static readonly PrivateKeyFormatter s_nsecPrivateKeyFormatter = new X25519PrivateKeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[]
        {
            0xDE, 0x36, 0x41, 0xDE, crypto_scalarmult_curve25519_SCALARBYTES, 0, 0, 0
        });

        private static readonly PublicKeyFormatter s_nsecPublicKeyFormatter = new X25519PublicKeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[]
        {
            0xDE, 0x37, 0x41, 0xDE, crypto_scalarmult_curve25519_SCALARBYTES, 0, 0, 0
        });

        private static readonly Oid s_oid = new Oid(1, 3, 101, 110);

        private static readonly PrivateKeyFormatter s_pkixPrivateKeyFormatter = new X25519PrivateKeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[]
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

        private static readonly PublicKeyFormatter s_pkixPublicKeyFormatter = new X25519PublicKeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[]
        {
            // +-- SEQUENCE (2 elements)
            //     +-- SEQUENCE (1 element)
            //     |   +-- OBJECT IDENTIFIER 1.3.101.110
            //     +-- BIT STRING (256 bits)
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
            0x6E, 0x03, 0x21, 0x00,
        });

        private static readonly PrivateKeyFormatter s_rawPrivateKeyFormatter = new X25519PrivateKeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[] { });

        private static readonly PublicKeyFormatter s_rawPublicKeyFormatter = new X25519PublicKeyFormatter(crypto_scalarmult_curve25519_SCALARBYTES, new byte[] { });

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public X25519() : base(
            privateKeySize: crypto_scalarmult_curve25519_SCALARBYTES,
            publicKeySize: crypto_scalarmult_curve25519_SCALARBYTES,
            sharedSecretSize: crypto_scalarmult_curve25519_BYTES)
        {
            if (!s_selfTest.Value)
            {
                throw Error.Cryptographic_InitializationFailed();
            }
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            Debug.Assert(seed.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            publicKeyBytes = new byte[crypto_scalarmult_curve25519_SCALARBYTES];
            SecureMemoryHandle.Alloc(crypto_scalarmult_curve25519_SCALARBYTES, out keyHandle);
            keyHandle.Import(seed);
            crypto_scalarmult_curve25519_base(publicKeyBytes, keyHandle);

            Debug.Assert((publicKeyBytes[crypto_scalarmult_curve25519_SCALARBYTES - 1] & 0x80) == 0);
        }

        internal override int GetDefaultSeedSize()
        {
            return crypto_scalarmult_curve25519_SCALARBYTES;
        }

        private protected override bool TryAgreeCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> otherPartyPublicKey,
            out SecureMemoryHandle sharedSecretHandle)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(otherPartyPublicKey.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            SecureMemoryHandle.Alloc(crypto_scalarmult_curve25519_BYTES, out sharedSecretHandle);

            int error = crypto_scalarmult_curve25519(
                sharedSecretHandle,
                keyHandle,
                ref otherPartyPublicKey.DangerousGetPinnableReference());

            return error == 0;
        }

        internal override bool TryExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPrivateKey:
                return s_rawPrivateKeyFormatter.TryExport(keyHandle, blob, out blobSize);
            case KeyBlobFormat.NSecPrivateKey:
                return s_nsecPrivateKeyFormatter.TryExport(keyHandle, blob, out blobSize);
            case KeyBlobFormat.PkixPrivateKey:
                return s_pkixPrivateKeyFormatter.TryExport(keyHandle, blob, out blobSize);
            case KeyBlobFormat.PkixPrivateKeyText:
                return s_pkixPrivateKeyFormatter.TryExportText(keyHandle, blob, out blobSize);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryExportPublicKey(
            ReadOnlySpan<byte> publicKeyBytes,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPublicKey:
                return s_rawPublicKeyFormatter.TryExport(publicKeyBytes, blob, out blobSize);
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.TryExport(publicKeyBytes, blob, out blobSize);
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.TryExport(publicKeyBytes, blob, out blobSize);
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.TryExportText(publicKeyBytes, blob, out blobSize);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
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

        private static bool SelfTest()
        {
            return (crypto_scalarmult_curve25519_bytes() == (UIntPtr)crypto_scalarmult_curve25519_BYTES)
                && (crypto_scalarmult_curve25519_scalarbytes() == (UIntPtr)crypto_scalarmult_curve25519_SCALARBYTES);
        }
    }
}
