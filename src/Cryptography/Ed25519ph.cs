using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  Ed25519ph
    //
    //      Digital Signature Algorithm based on the edwards25519 curve in
    //      pre-hash mode (HashEdDSA)
    //
    //  References:
    //
    //      RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)
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
    public sealed class Ed25519ph : SignatureAlgorithm2
    {
        private static readonly PrivateKeyFormatter s_nsecPrivateKeyFormatter = new Ed25519PrivateKeyFormatter([0xDE, 0x64, 0x48, 0xDE, crypto_sign_ed25519_SEEDBYTES, 0, crypto_sign_ed25519_BYTES, 0]);

        private static readonly PublicKeyFormatter s_nsecPublicKeyFormatter = new Ed25519PublicKeyFormatter([0xDE, 0x65, 0x48, 0xDE, crypto_sign_ed25519_PUBLICKEYBYTES, 0, crypto_sign_ed25519_BYTES, 0]);

        private static readonly PrivateKeyFormatter s_rawPrivateKeyFormatter = new Ed25519PrivateKeyFormatter([]);

        private static readonly PublicKeyFormatter s_rawPublicKeyFormatter = new Ed25519PublicKeyFormatter([]);

        private static int s_selfTest;

        public Ed25519ph() : base(
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
            out PublicKey? publicKey)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_sign_ed25519_PUBLICKEYBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(seed.Length == crypto_sign_ed25519_SEEDBYTES);

            publicKey = new PublicKey(this);
            keyHandle = SecureMemoryHandle.Create(crypto_sign_ed25519_SECRETKEYBYTES);

            int error = crypto_sign_ed25519_seed_keypair(
                ref publicKey.GetPinnableReference(),
                keyHandle,
                seed);

            Debug.Assert(error == 0);
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
            Debug.Assert(keyHandle.Size == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            crypto_sign_ed25519ph_state state;

            crypto_sign_ed25519ph_init(
                ref state);

            crypto_sign_ed25519ph_update(
                ref state,
                data,
                (ulong)data.Length);

            int error = crypto_sign_ed25519ph_final_create(
                 ref state,
                 signature,
                 out ulong siglen,
                 keyHandle);

            Debug.Assert(error == 0);
            Debug.Assert((ulong)signature.Length == siglen);
        }

        private protected override bool VerifyCore(
            ref readonly PublicKeyBytes publicKeyBytes,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_sign_ed25519_PUBLICKEYBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            crypto_sign_ed25519ph_state state;

            crypto_sign_ed25519ph_init(
                ref state);

            crypto_sign_ed25519ph_update(
                ref state,
                data,
                (ulong)data.Length);

            int error = crypto_sign_ed25519ph_final_verify(
                ref state,
                signature,
                in publicKeyBytes);

            return error == 0;
        }

        internal override void InitializeCore(
            out IncrementalSignatureState state)
        {
            int error = crypto_sign_ed25519ph_init(
                ref state.ed25519ph);

            Debug.Assert(error == 0);
        }

        internal override void UpdateCore(
            ref IncrementalSignatureState state,
            ReadOnlySpan<byte> data)
        {
            int error = crypto_sign_ed25519ph_update(
                ref state.ed25519ph,
                data,
                (ulong)data.Length);

            Debug.Assert(error == 0);
        }

        internal override void FinalSignCore(
            ref IncrementalSignatureState state,
            SecureMemoryHandle keyHandle,
            Span<byte> signature)
        {
            Debug.Assert(keyHandle.Size == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            int error = crypto_sign_ed25519ph_final_create(
                ref state.ed25519ph,
                signature,
                out ulong siglen,
                keyHandle);

            Debug.Assert(error == 0);
            Debug.Assert((ulong)signature.Length == siglen);
        }

        internal override bool FinalVerifyCore(
            ref IncrementalSignatureState state,
            ref readonly PublicKeyBytes publicKeyBytes,
            ReadOnlySpan<byte> signature)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_sign_ed25519_PUBLICKEYBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            int error = crypto_sign_ed25519ph_final_verify(
                ref state.ed25519ph,
                signature,
                in publicKeyBytes);

            return error == 0;
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
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        private static void SelfTest()
        {
            if ((crypto_sign_ed25519_bytes() != crypto_sign_ed25519_BYTES) ||
                (crypto_sign_ed25519_publickeybytes() != crypto_sign_ed25519_PUBLICKEYBYTES) ||
                (crypto_sign_ed25519_secretkeybytes() != crypto_sign_ed25519_SECRETKEYBYTES) ||
                (crypto_sign_ed25519_seedbytes() != crypto_sign_ed25519_SEEDBYTES) ||
                (crypto_sign_ed25519ph_statebytes() != (nuint)Unsafe.SizeOf<crypto_sign_ed25519ph_state>()))
            {
                throw Error.InvalidOperation_InitializationFailed();
            }
        }
    }
}
