using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Sequential)]
    public struct IncrementalHash
    {
        internal State InnerState;
        internal HashAlgorithm Algorithm;

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool Equals(
            object objA,
            object objB)
        {
            return object.Equals(objA, objB);
        }

        public static byte[] Finalize(
            ref IncrementalHash state)
        {
            if (state.Algorithm == null)
            {
                throw new InvalidOperationException();
            }

            try
            {
                byte[] hash = new byte[state.Algorithm.HashSize];
                state.Algorithm.FinalizeCore(ref state.InnerState, hash);
                return hash;
            }
            finally
            {
                state.Algorithm = null;
            }
        }

        public static void Finalize(
            ref IncrementalHash state,
            Span<byte> hash)
        {
            if (state.Algorithm == null)
            {
                throw new InvalidOperationException();
            }
            if (hash.Length != state.Algorithm.HashSize)
            {
                throw new ArgumentException();
            }

            try
            {
                state.Algorithm.FinalizeCore(ref state.InnerState, hash);
            }
            finally
            {
                state.Algorithm = null;
            }
        }

        public static bool FinalizeAndTryVerify(
            ref IncrementalHash state,
            ReadOnlySpan<byte> hash)
        {
            if (state.Algorithm == null)
            {
                throw new InvalidOperationException();
            }

            try
            {
                return hash.Length == state.Algorithm.HashSize && state.Algorithm.FinalizeAndTryVerifyCore(ref state.InnerState, hash);
            }
            finally
            {
                state.Algorithm = null;
            }
        }

        public static void FinalizeAndVerify(
            ref IncrementalHash state,
            ReadOnlySpan<byte> hash)
        {
            if (state.Algorithm == null)
            {
                throw new InvalidOperationException();
            }

            try
            {
                if (!(hash.Length == state.Algorithm.HashSize && state.Algorithm.FinalizeAndTryVerifyCore(ref state.InnerState, hash)))
                {
                    throw new CryptographicException();
                }
            }
            finally
            {
                state.Algorithm = null;
            }
        }

        public static void Initialize(
            HashAlgorithm algorithm,
            out IncrementalHash state)
        {
            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            bool success = false;
            try
            {
                algorithm.InitializeCore(out state.InnerState);
                state.Algorithm = algorithm;
                success = true;
            }
            finally
            {
                if (!success)
                {
                    state = default;
                }
            }
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool ReferenceEquals(
            object objA,
            object objB)
        {
            return object.ReferenceEquals(objA, objB);
        }

        public static void Update(
            ref IncrementalHash state,
            ReadOnlySpan<byte> data)
        {
            if (state.Algorithm == null)
            {
                throw new InvalidOperationException();
            }

            state.Algorithm.UpdateCore(ref state.InnerState, data);
        }

        public override bool Equals(
            object obj)
        {
            throw new NotSupportedException();
        }

        public override int GetHashCode()
        {
            throw new NotSupportedException();
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct State
        {
            [FieldOffset(0)]
            internal crypto_generichash_blake2b_state blake2b;

            [FieldOffset(0)]
            internal crypto_hash_sha256_state sha256;

            [FieldOffset(0)]
            internal crypto_hash_sha512_state sha512;
        }
    }
}
