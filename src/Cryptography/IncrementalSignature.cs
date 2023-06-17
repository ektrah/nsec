using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Sequential)]
    public readonly struct IncrementalSignature
    {
        private readonly IncrementalSignatureState _state;
        private readonly SignatureAlgorithm2? _algorithm;
        private readonly Key? _privateKey;

        public SignatureAlgorithm2? Algorithm => _algorithm;

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool Equals(
            object? objA,
            object? objB)
        {
            return object.Equals(objA, objB);
        }

        public static void Initialize(
            Key privateKey,
            out IncrementalSignature state)
        {
            if (privateKey == null)
            {
                throw Error.ArgumentNull_Key(nameof(privateKey));
            }
            if (privateKey.Algorithm is not SignatureAlgorithm2 algorithm)
            {
                throw Error.Argument_SignatureKeyRequired(nameof(privateKey));
            }

            state = default;
            algorithm.InitializeCore(out Unsafe.AsRef(in state._state));
            Unsafe.AsRef(in state._algorithm) = algorithm;
            Unsafe.AsRef(in state._privateKey) = privateKey;
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

        public static byte[] Finalize(
            ref IncrementalSignature state)
        {
            if (state._algorithm == null || state._privateKey == null)
            {
                throw Error.InvalidOperation_UninitializedState();
            }

            try
            {
                byte[] signature = new byte[state._algorithm.SignatureSize];
                state._algorithm.FinalSignCore(ref Unsafe.AsRef(in state._state), state._privateKey.Handle, signature);
                return signature;
            }
            finally
            {
                Unsafe.AsRef<SignatureAlgorithm2?>(in state._algorithm) = null;
                Unsafe.AsRef<Key?>(in state._privateKey) = null;
            }
        }

        public static void Finalize(
            ref IncrementalSignature state,
            Span<byte> signature)
        {
            if (state._algorithm == null || state._privateKey == null)
            {
                throw Error.InvalidOperation_UninitializedState();
            }
            if (signature.Length != state._algorithm.SignatureSize)
            {
                throw Error.Argument_SignatureLength(nameof(signature), state._algorithm.SignatureSize);
            }

            try
            {
                state._algorithm.FinalSignCore(ref Unsafe.AsRef(in state._state), state._privateKey.Handle, signature);
            }
            finally
            {
                Unsafe.AsRef<SignatureAlgorithm2?>(in state._algorithm) = null;
            }
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool ReferenceEquals(
            object? objA,
            object? objB)
        {
            return object.ReferenceEquals(objA, objB);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(
            object? obj)
        {
            throw Error.NotSupported_Operation();
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            throw Error.NotSupported_Operation();
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string? ToString()
        {
            return typeof(IncrementalSignature).ToString();
        }
    }
}
