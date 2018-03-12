using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Sequential)]
    public struct IncrementalMac
    {
        private State _innerState;
        private MacAlgorithm _algorithm;

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool Equals(
            object objA,
            object objB)
        {
            return object.Equals(objA, objB);
        }

        public static byte[] Finalize(
            ref IncrementalMac state)
        {
            if (state._algorithm == null)
            {
                throw new InvalidOperationException();
            }

            try
            {
                byte[] mac = new byte[state._algorithm.MacSize];
                state._algorithm.FinalizeCore(ref state._innerState, mac);
                return mac;
            }
            finally
            {
                state._algorithm = null;
            }
        }

        public static void Finalize(
            ref IncrementalMac state,
            Span<byte> mac)
        {
            if (state._algorithm == null)
            {
                throw new InvalidOperationException();
            }
            if (mac.Length != state._algorithm.MacSize)
            {
                throw new ArgumentException();
            }

            try
            {
                state._algorithm.FinalizeCore(ref state._innerState, mac);
            }
            finally
            {
                state._algorithm = null;
            }
        }

        public static bool FinalizeAndTryVerify(
            ref IncrementalMac state,
            ReadOnlySpan<byte> mac)
        {
            if (state._algorithm == null)
            {
                throw new InvalidOperationException();
            }

            try
            {
                return mac.Length == state._algorithm.MacSize && state._algorithm.FinalizeAndTryVerifyCore(ref state._innerState, mac);
            }
            finally
            {
                state._algorithm = null;
            }
        }

        public static void FinalizeAndVerify(
            ref IncrementalMac state,
            ReadOnlySpan<byte> mac)
        {
            if (state._algorithm == null)
            {
                throw new InvalidOperationException();
            }

            try
            {
                if (!(mac.Length == state._algorithm.MacSize && state._algorithm.FinalizeAndTryVerifyCore(ref state._innerState, mac)))
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
            Key key,
            out IncrementalMac state)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            if (!(key.Algorithm is MacAlgorithm algorithm))
            {
                throw new ArgumentException();
            }

            bool success = false;
            try
            {
                algorithm.InitializeCore(key.Handle, algorithm.MacSize, out state._innerState);
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
            ref IncrementalMac state,
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
            internal crypto_auth_hmacsha256_state hmacsha256;

            [FieldOffset(0)]
            internal crypto_auth_hmacsha512_state hmacsha512;
        }
    }
}
