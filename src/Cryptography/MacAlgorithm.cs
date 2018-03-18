using System;
using System.Diagnostics;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  A message authentication code (MAC) algorithm
    //
    //  Candidates
    //
    //      | Algorithm    | Reference       | Key Size | Customization | MAC Size |
    //      | ------------ | --------------- | -------- | ------------- | -------- |
    //      | AES-CMAC     | RFC 4493        | 16       | no            | 16       |
    //      | BLAKE2b      | RFC 7693        | 0..64    | no            | 1..64    |
    //      | HMAC-SHA-256 | RFC 2104        | any      | no            | 32       |
    //      | HMAC-SHA-512 | RFC 2104        | any      | no            | 64       |
    //      | KMAC128      | NIST SP 800-185 | any      | yes           | any      |
    //      | KMAC256      | NIST SP 800-185 | any      | yes           | any      |
    //      | KMACXOF128   | NIST SP 800-185 | any      | yes           | any      |
    //      | KMACXOF256   | NIST SP 800-185 | any      | yes           | any      |
    //
    public abstract class MacAlgorithm : Algorithm
    {
        private static Blake2bMac s_Blake2b_256;
        private static Blake2bMac s_Blake2b_512;
        private static HmacSha256 s_HmacSha256;
        private static HmacSha512 s_HmacSha512;

        private readonly int _defaultKeySize;
        private readonly int _macSize;
        private readonly int _maxKeySize;
        private readonly int _minKeySize;

        private protected MacAlgorithm(
            int minKeySize,
            int defaultKeySize,
            int maxKeySize,
            int macSize)
        {
            Debug.Assert(minKeySize >= 0);
            Debug.Assert(defaultKeySize > 0);
            Debug.Assert(defaultKeySize >= minKeySize);
            Debug.Assert(maxKeySize >= defaultKeySize);

            Debug.Assert(macSize > 0);

            _minKeySize = minKeySize;
            _defaultKeySize = defaultKeySize;
            _maxKeySize = maxKeySize;

            _macSize = macSize;
        }

        public static Blake2bMac Blake2b_256
        {
            get
            {
                Blake2bMac instance = s_Blake2b_256;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Blake2b_256, new Blake2bMac(256 / 8), null);
                    instance = s_Blake2b_256;
                }
                return instance;
            }
        }

        public static Blake2bMac Blake2b_512
        {
            get
            {
                Blake2bMac instance = s_Blake2b_512;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Blake2b_512, new Blake2bMac(512 / 8), null);
                    instance = s_Blake2b_512;
                }
                return instance;
            }
        }

        public static HmacSha256 HmacSha256
        {
            get
            {
                HmacSha256 instance = s_HmacSha256;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_HmacSha256, new HmacSha256(), null);
                    instance = s_HmacSha256;
                }
                return instance;
            }
        }

        public static HmacSha512 HmacSha512
        {
            get
            {
                HmacSha512 instance = s_HmacSha512;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_HmacSha512, new HmacSha512(), null);
                    instance = s_HmacSha512;
                }
                return instance;
            }
        }

        public int DefaultKeySize => _defaultKeySize;

        public int MacSize => _macSize;

        public int MaxKeySize => _maxKeySize;

        public int MinKeySize => _minKeySize;

        public byte[] Mac(
            Key key,
            ReadOnlySpan<byte> data)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            }

            byte[] mac = new byte[_macSize];
            MacCore(key.Handle, data, mac);
            return mac;
        }

        public void Mac(
            Key key,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            }
            if (mac.Length != _macSize)
            {
                throw Error.Argument_MacLength(nameof(mac), _macSize.ToString());
            }

            MacCore(key.Handle, data, mac);
        }

        public bool TryVerify(
            Key key,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            }

            return mac.Length == _macSize && TryVerifyCore(key.Handle, data, mac);
        }

        public void Verify(
            Key key,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            }

            if (!(mac.Length == _macSize && TryVerifyCore(key.Handle, data, mac)))
            {
                throw Error.Cryptographic_VerificationFailed();
            }
        }

        internal abstract bool FinalizeAndTryVerifyCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> mac);

        internal abstract void FinalizeCore(
            ref IncrementalMacState state,
            Span<byte> mac);

        internal abstract void InitializeCore(
            SecureMemoryHandle keyHandle,
            int macSize,
            out IncrementalMacState state);

        internal abstract void UpdateCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> data);

        private protected abstract void MacCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> mac);

        private protected abstract bool TryVerifyCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac);
    }
}
