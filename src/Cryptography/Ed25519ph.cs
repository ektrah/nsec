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
        private static readonly PrivateKeyFormatter s_nsecPrivateKeyFormatter = new Ed25519PrivateKeyFormatter(new byte[] { 0xDE, 0x64, 0x48, 0xDE, crypto_sign_ed25519_SEEDBYTES, 0, crypto_sign_ed25519_BYTES, 0 });

        private static readonly PublicKeyFormatter s_nsecPublicKeyFormatter = new Ed25519PublicKeyFormatter(new byte[] { 0xDE, 0x65, 0x48, 0xDE, crypto_sign_ed25519_PUBLICKEYBYTES, 0, crypto_sign_ed25519_BYTES, 0 });

        private static readonly PrivateKeyFormatter s_rawPrivateKeyFormatter = new Ed25519PrivateKeyFormatter(Array.Empty<byte>());

        private static readonly PublicKeyFormatter s_rawPublicKeyFormatter = new Ed25519PublicKeyFormatter(Array.Empty<byte>());

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

        internal override unsafe void CreateKey(
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

            fixed (PublicKeyBytes* pk = publicKey)
            fixed (byte* seed_ = seed)
            {
                int error = crypto_sign_ed25519_seed_keypair(pk, keyHandle, seed_);

                Debug.Assert(error == 0);
            }
        }

        internal override int GetSeedSize()
        {
            return crypto_sign_ed25519_SEEDBYTES;
        }

        private protected unsafe override void SignCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> signature)
        {
            Debug.Assert(keyHandle.Size == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            fixed (byte* sig = signature)
            fixed (byte* m = data)
            {
                crypto_sign_ed25519ph_state state;

                crypto_sign_ed25519ph_init(
                    &state);

                crypto_sign_ed25519ph_update(
                    &state,
                    m,
                    (ulong)data.Length);

                int error = crypto_sign_ed25519ph_final_create(
                     &state,
                     sig,
                     out ulong signatureLength,
                     keyHandle);

                Debug.Assert(error == 0);
                Debug.Assert((ulong)signature.Length == signatureLength);
            }
        }

        private protected unsafe override bool VerifyCore(
            in PublicKeyBytes publicKeyBytes,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_sign_ed25519_PUBLICKEYBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            fixed (byte* sig = signature)
            fixed (byte* m = data)
            fixed (PublicKeyBytes* pk = &publicKeyBytes)
            {
                crypto_sign_ed25519ph_state state;

                crypto_sign_ed25519ph_init(
                    &state);

                crypto_sign_ed25519ph_update(
                    &state,
                    m,
                    (ulong)data.Length);

                int error = crypto_sign_ed25519ph_final_verify(
                    &state,
                    sig,
                    pk);

                return error == 0;
            }
        }

        internal unsafe override void InitializeCore(
            out IncrementalSignatureState state)
        {
            fixed (crypto_sign_ed25519ph_state* state_ = &state.ed25519ph)
            {
                int error = crypto_sign_ed25519ph_init(state_);

                Debug.Assert(error == 0);
            }
        }

        internal unsafe override void UpdateCore(
            ref IncrementalSignatureState state,
            ReadOnlySpan<byte> data)
        {
            fixed (crypto_sign_ed25519ph_state* state_ = &state.ed25519ph)
            fixed (byte* @in = data)
            {
                int error = crypto_sign_ed25519ph_update(
                    state_,
                    @in,
                    (ulong)data.Length);

                Debug.Assert(error == 0);
            }
        }

        internal unsafe override void FinalSignCore(
            ref IncrementalSignatureState state,
            SecureMemoryHandle keyHandle,
            Span<byte> signature)
        {
            Debug.Assert(keyHandle.Size == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            fixed (crypto_sign_ed25519ph_state* state_ = &state.ed25519ph)
            fixed (byte* sig = signature)
            {
                int error = crypto_sign_ed25519ph_final_create(
                    state_,
                    sig,
                    out ulong signatureLength,
                    keyHandle);

                Debug.Assert(error == 0);
                Debug.Assert((ulong)signature.Length == signatureLength);
            }
        }

        internal unsafe override bool FinalVerifyCore(
            ref IncrementalSignatureState state,
            in PublicKeyBytes publicKeyBytes,
            ReadOnlySpan<byte> signature)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_sign_ed25519_PUBLICKEYBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            fixed (crypto_sign_ed25519ph_state* state_ = &state.ed25519ph)
            fixed (byte* sig = signature)
            fixed (PublicKeyBytes* pk = &publicKeyBytes)
            {
                int error = crypto_sign_ed25519ph_final_verify(
                    state_,
                    sig,
                    pk);

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
