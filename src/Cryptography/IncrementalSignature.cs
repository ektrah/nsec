using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Sequential)]
    public struct IncrementalSignature
    {
        private readonly IncrementalSignatureState _state;
        private readonly SignatureAlgorithm? _algorithm;

        public SignatureAlgorithm? Algorithm => _algorithm;

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool Equals(
            object? objA,
            object? objB)
        {
            return object.Equals(objA, objB);
        }

        public static void Initialize(
            SignatureAlgorithm algorithm,
            out IncrementalSignature state)
        {
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            if (!algorithm.SupportsPartialUpdated)
            {
                throw Error.NotSupported_Algorithm();
            }

            state = default;
            algorithm.InitializeCore(out Unsafe.AsRef(in state._state));
            Unsafe.AsRef(in state._algorithm) = algorithm;
        }

        public static void Update(
            ref IncrementalSignature state,
            ReadOnlySpan<byte> data)
        {
            if (state._algorithm == null)
            {
                throw Error.InvalidOperation_UninitializedState();
            }

            state._algorithm.UpdateCore(ref Unsafe.AsRef(in state._state), data);
        }

        public static byte[] FinalSignature(
            ref IncrementalSignature state,
            Key key)
        {
            if (state._algorithm == null)
            {
                throw Error.InvalidOperation_UninitializedState();
            }

            try
            {
                byte[] signature = new byte[state._algorithm.SignatureSize];
                state._algorithm.FinalSignCore(ref Unsafe.AsRef(in state._state), key.Handle, signature);
                return signature;
            }
            finally
            {
                Unsafe.AsRef<SignatureAlgorithm?>(in state._algorithm) = null;
            }
        }

        public static void FinalSignature(
            ref IncrementalSignature state,
            Key key,
            Span<byte> signature)
        {
            if (state._algorithm == null)
            {
                throw Error.InvalidOperation_UninitializedState();
            }
            if (signature.Length != state._algorithm.SignatureSize)
            {
                throw Error.Argument_SignatureLength(nameof(signature), state._algorithm.SignatureSize);
            }

            try
            {
                state._algorithm.FinalSignCore(ref Unsafe.AsRef(in state._state), key.Handle, signature);
            }
            finally
            {
                Unsafe.AsRef<SignatureAlgorithm?>(in state._algorithm) = null;
            }
        }

        public static bool FinalVerify(
            ref IncrementalSignature state,
            PublicKey publicKey,
            ReadOnlySpan<byte> signature)
        {
            if (state._algorithm == null)
            {
                throw Error.InvalidOperation_UninitializedState();
            }
            if (publicKey == null)
            {
                throw Error.ArgumentNull_Key(nameof(publicKey));
            }
            if (publicKey.Algorithm != state._algorithm)
            {
                throw Error.Argument_PublicKeyAlgorithmMismatch(nameof(publicKey), nameof(publicKey));
            }

            try
            {
                return signature.Length == state._algorithm.SignatureSize &&
                       state._algorithm.FinalVerifyCore(ref Unsafe.AsRef(in state._state), publicKey.GetPinnableReference(), signature);
            }
            finally
            {
                Unsafe.AsRef<SignatureAlgorithm?>(in state._algorithm) = null;
            }
        }
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct IncrementalSignatureState
    {
        [FieldOffset(0)]
        internal Interop.Libsodium.crypto_sign_ed25519ph_state ed25519PhState;
    }
}
