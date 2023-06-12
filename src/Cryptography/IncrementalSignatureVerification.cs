using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Sequential)]
    public readonly struct IncrementalSignatureVerification
    {
        private readonly IncrementalSignatureState _state;
        private readonly SignatureAlgorithm2? _algorithm;

        private readonly PublicKey? _publicKey;

        public SignatureAlgorithm2? Algorithm => _algorithm;

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool Equals(
            object? objA,
            object? objB)
        {
            return object.Equals(objA, objB);
        }

        public static void Initialize(
            SignatureAlgorithm2 algorithm,
            PublicKey publicKey,
            out IncrementalSignatureVerification state)
        {
            if (algorithm == null)
            {
                throw Error.ArgumentNull_Algorithm(nameof(algorithm));
            }

            if (publicKey == null)
            {
                throw Error.ArgumentNull_Key(nameof(publicKey));
            }
            if (publicKey.Algorithm != algorithm)
            {
                throw Error.Argument_PublicKeyAlgorithmMismatch(nameof(publicKey), nameof(publicKey));
            }

            state = default;
            algorithm.InitializeCore(out Unsafe.AsRef(in state._state));
            Unsafe.AsRef(in state._algorithm) = algorithm;
            Unsafe.AsRef(in state._publicKey) = publicKey;
        }

        public static void Update(
            ref IncrementalSignatureVerification state,
            ReadOnlySpan<byte> data)
        {
            if (state._algorithm == null)
            {
                throw Error.InvalidOperation_UninitializedState();
            }

            state._algorithm.UpdateCore(ref Unsafe.AsRef(in state._state), data);
        }

        public static bool FinalizeAndVerify(
            ref IncrementalSignatureVerification state,
            ReadOnlySpan<byte> signature)
        {
            if (state._algorithm == null)
            {
                throw Error.InvalidOperation_UninitializedState();
            }

            if (state._publicKey == null)
            {
                throw Error.InvalidOperation_UninitializedState();
            }

            try
            {
                return signature.Length == state._algorithm.SignatureSize &&
                       state._algorithm.FinalVerifyCore(ref Unsafe.AsRef(in state._state), state._publicKey.GetPinnableReference(), signature);
            }
            finally
            {
                Unsafe.AsRef<SignatureAlgorithm2?>(in state._algorithm) = null;
                Unsafe.AsRef<PublicKey?>(in state._publicKey) = null;
            }
        }
    }
}
