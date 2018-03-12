using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Sequential)]
    public struct IncrementalHash
    {
        private State _innerState;
        private HashAlgorithm _algorithm;

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
            if (state._algorithm == null)
            {
                throw new InvalidOperationException();
            }

            try
            {
                byte[] hash = new byte[state._algorithm.HashSize];
                state._algorithm.FinalizeCore(ref state._innerState, hash);
                return hash;
            }
            finally
            {
                state._algorithm = null;
            }
        }

        public static void Finalize(
            ref IncrementalHash state,
            Span<byte> hash)
        {
            if (state._algorithm == null)
            {
                throw new InvalidOperationException();
            }
            if (hash.Length != state._algorithm.HashSize)
            {
                throw new ArgumentException();
            }

            try
            {
                state._algorithm.FinalizeCore(ref state._innerState, hash);
            }
            finally
            {
                state._algorithm = null;
            }
        }

        public static bool FinalizeAndTryVerify(
            ref IncrementalHash state,
            ReadOnlySpan<byte> hash)
        {
            if (state._algorithm == null)
            {
                throw new InvalidOperationException();
            }

            try
            {
                return hash.Length == state._algorithm.HashSize && state._algorithm.FinalizeAndTryVerifyCore(ref state._innerState, hash);
            }
            finally
            {
                state._algorithm = null;
            }
        }

        public static void FinalizeAndVerify(
            ref IncrementalHash state,
            ReadOnlySpan<byte> hash)
        {
            if (state._algorithm == null)
            {
                throw new InvalidOperationException();
            }

            try
            {
                if (!(hash.Length == state._algorithm.HashSize && state._algorithm.FinalizeAndTryVerifyCore(ref state._innerState, hash)))
                {
                    throw new CryptographicException();
                }
            }
            finally
            {
                state._algorithm = null;
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
                algorithm.InitializeCore(algorithm.HashSize, out state._innerState);
                state._algorithm = algorithm;
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
            if (state._algorithm == null)
            {
                throw new InvalidOperationException();
            }

            state._algorithm.UpdateCore(ref state._innerState, data);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(
            object obj)
        {
            throw new NotSupportedException();
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            throw new NotSupportedException();
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string ToString()
        {
            return GetType().ToString();
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
