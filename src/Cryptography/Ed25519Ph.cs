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
    //      Digital Signature Algorithm (EdDSA) pre-hashed based on the edwards25519 curve
    //
    //  References:
    //
    //      RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)
    //
    //      RFC 5958 - Asymmetric Key Packages
    //
    //      RFC 8410 - Algorithm Identifiers for Ed25519, Ed448, X25519, and
    //          X448 for Use in the Internet X.509 Public Key Infrastructure
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
    public sealed class Ed25519Ph : Ed25519
    {
        public override bool SupportsPartialUpdated => true;

        private protected override void SignCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> signature)
        {
            Debug.Assert(keyHandle.Size == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            InitializeCore(out IncrementalSignatureState state);
            UpdateCore(ref state, data);
            FinalSignCore(ref state, keyHandle, signature);
        }

        private protected override bool VerifyCore(
            in PublicKeyBytes publicKeyBytes,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signature)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_sign_ed25519_PUBLICKEYBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            InitializeCore(out IncrementalSignatureState state);
            UpdateCore(ref state, data);
            return FinalVerifyCore(ref state, publicKeyBytes, signature);
        }

        internal unsafe override void InitializeCore(
            out IncrementalSignatureState state)
        {
            fixed (crypto_sign_ed25519ph_state* state_ = &state.ed25519PhState)
            {
                int error = crypto_sign_ed25519ph_init(state_);

                Debug.Assert(error == 0);
            }
        }

        internal unsafe override void UpdateCore(
            ref IncrementalSignatureState state,
            ReadOnlySpan<byte> data)
        {
            fixed (crypto_sign_ed25519ph_state* state_ = &state.ed25519PhState)
            fixed (byte* @in = data)
            {
                int error = crypto_sign_ed25519ph_update(state_, @in, (ulong)data.Length);

                Debug.Assert(error == 0);
            }
        }

        internal unsafe override void FinalSignCore(ref IncrementalSignatureState state, SecureMemoryHandle keyHandle, Span<byte> signature)
        {
            Debug.Assert(keyHandle.Size == crypto_sign_ed25519_SECRETKEYBYTES);
            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            fixed (crypto_sign_ed25519ph_state* state_ = &state.ed25519PhState)
            fixed (byte* sig = signature)
            {
                int error = crypto_sign_ed25519ph_final_create(state_, sig, out ulong signatureLength, keyHandle);

                Debug.Assert(error == 0);
                Debug.Assert((ulong)signature.Length == signatureLength);
            }
        }

        internal unsafe override bool FinalVerifyCore(ref IncrementalSignatureState state, in PublicKeyBytes publicKeyBytes, ReadOnlySpan<byte> signature)
        {
            if (Unsafe.SizeOf<PublicKeyBytes>() != crypto_sign_ed25519_PUBLICKEYBYTES)
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(signature.Length == crypto_sign_ed25519_BYTES);

            fixed (crypto_sign_ed25519ph_state* state_ = &state.ed25519PhState)
            fixed (byte* sig = signature)
            fixed (PublicKeyBytes* pk = &publicKeyBytes)
            {
                int error = crypto_sign_ed25519ph_final_verify(state_, sig, pk);

                return error == 0;
            }
        }
    }
}
