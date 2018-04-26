using System;
using System.Buffers;
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
    //      draft-ietf-curdle-pkix-07 - Algorithm Identifiers for Ed25519,
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
        private static readonly PrivateKeyFormatter s_nsecPrivateKeyFormatter = new X25519PrivateKeyFormatter(new byte[] { 0xDE, 0x66, 0x41, 0xDE, crypto_scalarmult_curve25519_SCALARBYTES, 0, crypto_scalarmult_curve25519_BYTES, 0 });

        private static readonly PublicKeyFormatter s_nsecPublicKeyFormatter = new X25519PublicKeyFormatter(new byte[] { 0xDE, 0x67, 0x41, 0xDE, crypto_scalarmult_curve25519_SCALARBYTES, 0, crypto_scalarmult_curve25519_BYTES, 0 });

        private static readonly PrivateKeyFormatter s_pkixPrivateKeyFormatter = new X25519PrivateKeyFormatter(new byte[]
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

        private static readonly PublicKeyFormatter s_pkixPublicKeyFormatter = new X25519PublicKeyFormatter(new byte[]
        {
            // +-- SEQUENCE (2 elements)
            //     +-- SEQUENCE (1 element)
            //     |   +-- OBJECT IDENTIFIER 1.3.101.110
            //     +-- BIT STRING (256 bits)
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
            0x6E, 0x03, 0x21, 0x00,
        });

        private static readonly PrivateKeyFormatter s_rawPrivateKeyFormatter = new X25519PrivateKeyFormatter(new byte[] { });

        private static readonly PublicKeyFormatter s_rawPublicKeyFormatter = new X25519PublicKeyFormatter(new byte[] { });

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

        internal override void CreateKey(
            ReadOnlySpan<byte> seed,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKey publicKey)
        {
            Debug.Assert(seed.Length == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(Unsafe.SizeOf<PublicKeyBytes>() == crypto_scalarmult_curve25519_SCALARBYTES);

            publicKey = new PublicKey(this);
            owner = memoryPool.Rent(crypto_scalarmult_curve25519_SCALARBYTES);
            memory = owner.Memory.Slice(0, crypto_scalarmult_curve25519_SCALARBYTES);
            seed.CopyTo(owner.Memory.Span);
            crypto_scalarmult_curve25519_base(out publicKey.GetPinnableReference(), in owner.Memory.Span.GetPinnableReference());

            Debug.Assert((Unsafe.Add(ref Unsafe.As<PublicKeyBytes, byte>(ref publicKey.GetPinnableReference()), crypto_scalarmult_curve25519_SCALARBYTES - 1) & 0x80) == 0);
        }

        internal override int GetSeedSize()
        {
            return crypto_scalarmult_curve25519_SCALARBYTES;
        }

        private protected override bool TryAgreeCore(
            ReadOnlySpan<byte> key,
            in PublicKeyBytes otherPartyPublicKey,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner)
        {
            Debug.Assert(key.Length == crypto_scalarmult_curve25519_SCALARBYTES);
            Debug.Assert(Unsafe.SizeOf<PublicKeyBytes>() == crypto_scalarmult_curve25519_SCALARBYTES);

            owner = memoryPool.Rent(crypto_scalarmult_curve25519_BYTES);
            memory = owner.Memory.Slice(0, crypto_scalarmult_curve25519_BYTES);

            int error = crypto_scalarmult_curve25519(
                out owner.Memory.Span.GetPinnableReference(),
                in key.GetPinnableReference(),
                in otherPartyPublicKey);

            return error == 0;
        }

        internal override bool TryExportKey(
            ReadOnlySpan<byte> key,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPrivateKey:
                return s_rawPrivateKeyFormatter.TryExport(key, blob, out blobSize);
            case KeyBlobFormat.NSecPrivateKey:
                return s_nsecPrivateKeyFormatter.TryExport(key, blob, out blobSize);
            case KeyBlobFormat.PkixPrivateKey:
                return s_pkixPrivateKeyFormatter.TryExport(key, blob, out blobSize);
            case KeyBlobFormat.PkixPrivateKeyText:
                return s_pkixPrivateKeyFormatter.TryExportText(key, blob, out blobSize);
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
                return s_rawPublicKeyFormatter.TryExport(in publicKey.GetPinnableReference(), blob, out blobSize);
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.TryExport(in publicKey.GetPinnableReference(), blob, out blobSize);
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.TryExport(in publicKey.GetPinnableReference(), blob, out blobSize);
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.TryExportText(in publicKey.GetPinnableReference(), blob, out blobSize);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKey publicKey)
        {
            publicKey = new PublicKey(this);

            switch (format)
            {
            case KeyBlobFormat.RawPrivateKey:
                return s_rawPrivateKeyFormatter.TryImport(blob, memoryPool, out memory, out owner, out publicKey.GetPinnableReference());
            case KeyBlobFormat.NSecPrivateKey:
                return s_nsecPrivateKeyFormatter.TryImport(blob, memoryPool, out memory, out owner, out publicKey.GetPinnableReference());
            case KeyBlobFormat.PkixPrivateKey:
                return s_pkixPrivateKeyFormatter.TryImport(blob, memoryPool, out memory, out owner, out publicKey.GetPinnableReference());
            case KeyBlobFormat.PkixPrivateKeyText:
                return s_pkixPrivateKeyFormatter.TryImportText(blob, memoryPool, out memory, out owner, out publicKey.GetPinnableReference());
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
                return s_rawPublicKeyFormatter.TryImport(blob, out publicKey.GetPinnableReference());
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.TryImport(blob, out publicKey.GetPinnableReference());
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.TryImport(blob, out publicKey.GetPinnableReference());
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.TryImportText(blob, out publicKey.GetPinnableReference());
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        private static void SelfTest()
        {
            if ((crypto_scalarmult_curve25519_bytes() != (UIntPtr)crypto_scalarmult_curve25519_BYTES) ||
                (crypto_scalarmult_curve25519_scalarbytes() != (UIntPtr)crypto_scalarmult_curve25519_SCALARBYTES))
            {
                throw Error.Cryptographic_InitializationFailed();
            }
        }
    }
}
