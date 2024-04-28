using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
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
    //      RFC 8410 - Algorithm Identifiers for Ed25519, Ed448, X25519, and
    //          X448 for Use in the Internet X.509 Public Key Infrastructure
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
        private static readonly PrivateKeyFormatter s_nsecPrivateKeyFormatter = new X25519PrivateKeyFormatter([0xDE, 0x66, 0x41, 0xDE, crypto_scalarmult_curve25519_SCALARBYTES, 0, crypto_scalarmult_curve25519_BYTES, 0]);

        private static readonly PublicKeyFormatter s_nsecPublicKeyFormatter = new X25519PublicKeyFormatter([0xDE, 0x67, 0x41, 0xDE, crypto_scalarmult_curve25519_SCALARBYTES, 0, crypto_scalarmult_curve25519_BYTES, 0]);

        private static readonly PrivateKeyFormatter s_pkixPrivateKeyFormatter = new X25519PrivateKeyFormatter([
            // +-- SEQUENCE (3 elements)
            //     +-- INTEGER 0
            //     +-- SEQUENCE (1 element)
            //     |   +-- OBJECT IDENTIFIER 1.3.101.110
            //     +-- OCTET STRING (1 element)
            //         +-- OCTET STRING (32 bytes)
            0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
            0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20,
        ]);

        private static readonly PublicKeyFormatter s_pkixPublicKeyFormatter = new X25519PublicKeyFormatter([
            // +-- SEQUENCE (2 elements)
            //     +-- SEQUENCE (1 element)
            //     |   +-- OBJECT IDENTIFIER 1.3.101.110
            //     +-- BIT STRING (256 bits)
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
            0x6E, 0x03, 0x21, 0x00,
        ]);

        private static readonly PrivateKeyFormatter s_rawPrivateKeyFormatter = new X25519PrivateKeyFormatter([]);

        private static readonly PublicKeyFormatter s_rawPublicKeyFormatter = new X25519PublicKeyFormatter([]);

        private static int s_selfTest;

        public X25519() : base(
            privateKeySize: crypto_scalarmult_curve25519_SCALARBYTES,
            publicKeySize: crypto_scalarmult_curve25519_SCALARBYTES,
            sharedSecretSize: crypto_scalarmult_curve25519_BYTES)
        {
            if (s_selfTest == 0)
            {
                SelfTest();
                Interlocked.Exchange(ref s_selfTest, 1);
            }
        }

        internal override unsafe void CreateKey(
            ReadOnlySpan<byte> seed,
            out SecureMemoryHandle keyHandle,
            out PublicKey? publicKey)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_scalarmult_curve25519_SCALARBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(seed.Length == crypto_scalarmult_curve25519_SCALARBYTES);

            publicKey = new PublicKey(this);
            keyHandle = SecureMemoryHandle.CreateFrom(seed);

            fixed (PublicKeyBytes* q = publicKey)
            {
                int error = crypto_scalarmult_curve25519_base(q, keyHandle);

                Debug.Assert(error == 0);
                Debug.Assert((((byte*)q)[crypto_scalarmult_curve25519_SCALARBYTES - 1] & 0x80) == 0);
            }
        }

        internal override int GetSeedSize()
        {
            return crypto_scalarmult_curve25519_SCALARBYTES;
        }

        private protected unsafe override bool AgreeCore(
            SecureMemoryHandle keyHandle,
            ref readonly PublicKeyBytes otherPartyPublicKey,
            out SecureMemoryHandle? sharedSecretHandle)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_scalarmult_curve25519_SCALARBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(keyHandle.Size == crypto_scalarmult_curve25519_SCALARBYTES);

            sharedSecretHandle = SecureMemoryHandle.Create(crypto_scalarmult_curve25519_BYTES);

            fixed (PublicKeyBytes* p = &otherPartyPublicKey)
            {
                int error = crypto_scalarmult_curve25519(sharedSecretHandle, keyHandle, p);

                return error == 0;
            }
        }

        internal override bool TryExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            return format switch
            {
                KeyBlobFormat.RawPrivateKey => s_rawPrivateKeyFormatter.TryExport(keyHandle, blob, out blobSize),
                KeyBlobFormat.NSecPrivateKey => s_nsecPrivateKeyFormatter.TryExport(keyHandle, blob, out blobSize),
                KeyBlobFormat.PkixPrivateKey => s_pkixPrivateKeyFormatter.TryExport(keyHandle, blob, out blobSize),
                KeyBlobFormat.PkixPrivateKeyText => s_pkixPrivateKeyFormatter.TryExportText(keyHandle, blob, out blobSize),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        internal override bool TryExportPublicKey(
            PublicKey publicKey,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            return format switch
            {
                KeyBlobFormat.RawPublicKey => s_rawPublicKeyFormatter.TryExport(in publicKey.GetPinnableReference(), blob, out blobSize),
                KeyBlobFormat.NSecPublicKey => s_nsecPublicKeyFormatter.TryExport(in publicKey.GetPinnableReference(), blob, out blobSize),
                KeyBlobFormat.PkixPublicKey => s_pkixPublicKeyFormatter.TryExport(in publicKey.GetPinnableReference(), blob, out blobSize),
                KeyBlobFormat.PkixPublicKeyText => s_pkixPublicKeyFormatter.TryExportText(in publicKey.GetPinnableReference(), blob, out blobSize),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle? keyHandle,
            out PublicKey? publicKey)
        {
            publicKey = new PublicKey(this);

            return format switch
            {
                KeyBlobFormat.RawPrivateKey => s_rawPrivateKeyFormatter.TryImport(blob, out keyHandle, out publicKey.GetPinnableReference()),
                KeyBlobFormat.NSecPrivateKey => s_nsecPrivateKeyFormatter.TryImport(blob, out keyHandle, out publicKey.GetPinnableReference()),
                KeyBlobFormat.PkixPrivateKey => s_pkixPrivateKeyFormatter.TryImport(blob, out keyHandle, out publicKey.GetPinnableReference()),
                KeyBlobFormat.PkixPrivateKeyText => s_pkixPrivateKeyFormatter.TryImportText(blob, out keyHandle, out publicKey.GetPinnableReference()),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        internal override bool TryImportPublicKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out PublicKey publicKey)
        {
            publicKey = new PublicKey(this);

            return format switch
            {
                KeyBlobFormat.RawPublicKey => s_rawPublicKeyFormatter.TryImport(blob, out publicKey.GetPinnableReference()),
                KeyBlobFormat.NSecPublicKey => s_nsecPublicKeyFormatter.TryImport(blob, out publicKey.GetPinnableReference()),
                KeyBlobFormat.PkixPublicKey => s_pkixPublicKeyFormatter.TryImport(blob, out publicKey.GetPinnableReference()),
                KeyBlobFormat.PkixPublicKeyText => s_pkixPublicKeyFormatter.TryImportText(blob, out publicKey.GetPinnableReference()),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        private static void SelfTest()
        {
            if ((crypto_scalarmult_curve25519_bytes() != crypto_scalarmult_curve25519_BYTES) ||
                (crypto_scalarmult_curve25519_scalarbytes() != crypto_scalarmult_curve25519_SCALARBYTES))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
