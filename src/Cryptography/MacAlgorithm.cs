using System;
using System.Diagnostics;
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
        private readonly int _defaultKeySize;
        private readonly int _defaultMacSize;
        private readonly int _maxKeySize;
        private readonly int _maxMacSize;
        private readonly int _minKeySize;
        private readonly int _minMacSize;

        internal MacAlgorithm(
            int minKeySize,
            int defaultKeySize,
            int maxKeySize,
            int minMacSize,
            int defaultMacSize,
            int maxMacSize)
        {
            Debug.Assert(minKeySize >= 0);
            Debug.Assert(defaultKeySize > 0);
            Debug.Assert(defaultKeySize >= minKeySize);
            Debug.Assert(maxKeySize >= defaultKeySize);

            Debug.Assert(minMacSize >= 0);
            Debug.Assert(defaultMacSize > 0);
            Debug.Assert(defaultMacSize >= minMacSize);
            Debug.Assert(maxMacSize >= defaultMacSize);

            _minKeySize = minKeySize;
            _defaultKeySize = defaultKeySize;
            _maxKeySize = maxKeySize;

            _minMacSize = minMacSize;
            _defaultMacSize = defaultMacSize;
            _maxMacSize = maxMacSize;
        }

        public int DefaultKeySize => _defaultKeySize;

        public int DefaultMacSize => _defaultMacSize;

        public int MaxKeySize => _maxKeySize;

        public int MaxMacSize => _maxMacSize;

        public int MinKeySize => _minKeySize;

        public int MinMacSize => _minMacSize;

        public byte[] Sign(
            Key key,
            ReadOnlySpan<byte> data)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);

            byte[] mac = new byte[_defaultMacSize];
            SignCore(key.Handle, data, mac);
            return mac;
        }

        public byte[] Sign(
            Key key,
            ReadOnlySpan<byte> data,
            int macSize)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (macSize < _minMacSize || macSize > _maxMacSize)
                throw Error.ArgumentOutOfRange_MacSize(nameof(macSize), macSize.ToString(), _minMacSize.ToString(), _maxMacSize.ToString());

            byte[] mac = new byte[macSize];
            SignCore(key.Handle, data, mac);
            return mac;
        }

        public void Sign(
            Key key,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (mac.Length < _minMacSize || mac.Length > _maxMacSize)
                throw Error.Argument_MacSize(nameof(mac), mac.Length.ToString(), _minMacSize.ToString(), _maxMacSize.ToString());

            SignCore(key.Handle, data, mac);
        }

        public bool TryVerify(
            Key key,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (mac.Length < _minMacSize || mac.Length > _maxMacSize)
                return false;

            return TryVerifyCore(key.Handle, data, mac);
        }

        public void Verify(
            Key key,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (mac.Length < _minMacSize || mac.Length > _maxMacSize)
                throw Error.Argument_MacSize(nameof(mac), mac.Length.ToString(), _minMacSize.ToString(), _maxMacSize.ToString());

            if (!TryVerifyCore(key.Handle, data, mac))
            {
                throw Error.Cryptographic_VerificationFailed();
            }
        }

        internal abstract void SignCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            Span<byte> mac);

        internal abstract bool TryVerifyCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac);
    }
}
