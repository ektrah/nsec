using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
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
    //      RFC 5958 - Asymmetric Key Packages
    //
    //      draft-ietf-curdle-pkix-07 - Algorithm Identifiers for Ed25519,
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
        private static readonly PrivateKeyFormatter s_nsecPrivateKeyFormatter = new Ed25519PrivateKeyFormatter(new byte[] { 0xDE, 0x64, 0x42, 0xDE, crypto_sign_ed25519_SEEDBYTES, 0, crypto_sign_ed25519_BYTES, 0 });

        private static readonly PublicKeyFormatter s_nsecPublicKeyFormatter = new Ed25519PublicKeyFormatter(new byte[] { 0xDE, 0x65, 0x42, 0xDE, crypto_sign_ed25519_PUBLICKEYBYTES, 0, crypto_sign_ed25519_BYTES, 0 });

        private static readonly PrivateKeyFormatter s_pkixPrivateKeyFormatter = new Ed25519PrivateKeyFormatter(new byte[]
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

        private static readonly PublicKeyFormatter s_pkixPublicKeyFormatter = new Ed25519PublicKeyFormatter(new byte[]
        {
            // +-- SEQUENCE (2 elements)
            //     +-- SEQUENCE (1 element)
            //     |   +-- OBJECT IDENTIFIER 1.3.101.112
            //     +-- BIT STRING (256 bits)
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
            0x70, 0x03, 0x21, 0x00,
        });

        private static readonly PrivateKeyFormatter s_rawPrivateKeyFormatter = new Ed25519PrivateKeyFormatter(new byte[] { });

        private static readonly PublicKeyFormatter s_rawPublicKeyFormatter = new Ed25519PublicKeyFormatter(new byte[] { });

        private static int s_selfTest;

        public Ed25519() : base(
            privateKeySize: crypto_sign_ed25519_SEEDBYTES,
            publicKeySize: crypto_sign_ed25519_PUBLICKEYBYTES,
            signatureSize: crypto_sign_ed25519_BYTES)
        {
            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out PublicKey publicKey)
        {
            Debug.Assert(seed.Length == crypto_sign_ed25519_SEEDBYTES);
            Debug.Assert(Unsafe.SizeOf<PublicKeyBytes>() == crypto_sign_ed25519_PUBLICKEYBYTES);

            publicKey = new PublicKey(this);
            SecureMemoryHandle.Alloc(crypto_sign_ed25519_SECRETKEYBYTES, out keyHandle);
            crypto_sign_ed25519_seed_keypair(out publicKey.Bytes, keyHandle, in MemoryMarshal.GetReference(seed));
        }

        internal override int GetSeedSize()
        {
            return crypto_sign_ed25519_SEEDBYTES;
        }

        private protected override void SignCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> signature)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            crypto_sign_ed25519_detached(
                ref MemoryMarshal.GetReference(signature),
                out ulong signatureLength,
                in MemoryMarshal.GetReference(data),
                (ulong)data.Length,
                keyHandle);

            Debug.Assert((ulong)signature.Length == signatureLength);
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
            PublicKey publicKey,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPublicKey:
                return s_rawPublicKeyFormatter.TryExport(in publicKey.Bytes, blob, out blobSize);
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.TryExport(in publicKey.Bytes, blob, out blobSize);
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.TryExport(in publicKey.Bytes, blob, out blobSize);
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.TryExportText(in publicKey.Bytes, blob, out blobSize);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle keyHandle,
            out PublicKey publicKey)
        {
            publicKey = new PublicKey(this);

            switch (format)
            {
            case KeyBlobFormat.RawPrivateKey:
                return s_rawPrivateKeyFormatter.TryImport(blob, out keyHandle, out publicKey.Bytes);
            case KeyBlobFormat.NSecPrivateKey:
                return s_nsecPrivateKeyFormatter.TryImport(blob, out keyHandle, out publicKey.Bytes);
            case KeyBlobFormat.PkixPrivateKey:
                return s_pkixPrivateKeyFormatter.TryImport(blob, out keyHandle, out publicKey.Bytes);
            case KeyBlobFormat.PkixPrivateKeyText:
                return s_pkixPrivateKeyFormatter.TryImportText(blob, out keyHandle, out publicKey.Bytes);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryImportPublicKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out PublicKey publicKey)
        {
            publicKey = new PublicKey(this);

            switch (format)
            {
            case KeyBlobFormat.RawPublicKey:
                return s_rawPublicKeyFormatter.TryImport(blob, out publicKey.Bytes);
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.TryImport(blob, out publicKey.Bytes);
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.TryImport(blob, out publicKey.Bytes);
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.TryImportText(blob, out publicKey.Bytes);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        private protected override bool TryVerifyCore(
            in PublicKeyBytes publicKeyBytes,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            Debug.Assert(Unsafe.SizeOf<PublicKeyBytes>() == crypto_sign_ed25519_PUBLICKEYBYTES);
            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            int error = crypto_sign_ed25519_verify_detached(
                in MemoryMarshal.GetReference(signature),
                in MemoryMarshal.GetReference(data),
                (ulong)data.Length,
                in publicKeyBytes);

            return error == 0;
        }

        private static void SelfTest()
        {
            if ((crypto_sign_ed25519_bytes() != (UIntPtr)crypto_sign_ed25519_BYTES) ||
                (crypto_sign_ed25519_publickeybytes() != (UIntPtr)crypto_sign_ed25519_PUBLICKEYBYTES) ||
                (crypto_sign_ed25519_secretkeybytes() != (UIntPtr)crypto_sign_ed25519_SECRETKEYBYTES) ||
                (crypto_sign_ed25519_seedbytes() != (UIntPtr)crypto_sign_ed25519_SEEDBYTES))
            {
                throw Error.Cryptographic_InitializationFailed();
            }
        }
    }
}
