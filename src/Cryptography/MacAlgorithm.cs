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
        private static Blake2bMac? s_Blake2b_128;
        private static Blake2bMac? s_Blake2b_256;
        private static Blake2bMac? s_Blake2b_512;
        private static HmacSha256? s_HmacSha256;
        private static HmacSha256? s_HmacSha256_128;
        private static HmacSha512? s_HmacSha512;
        private static HmacSha512? s_HmacSha512_256;

        private readonly int _keySize;
        private readonly int _macSize;

        private protected MacAlgorithm(
            int keySize,
            int macSize)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(macSize > 0);

            _keySize = keySize;
            _macSize = macSize;
        }

        public static Blake2bMac Blake2b_128
        {
            get
            {
                Blake2bMac? instance = s_Blake2b_128;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Blake2b_128, new Blake2bMac(crypto_generichash_blake2b_KEYBYTES, 128 / 8), null);
                    instance = s_Blake2b_128;
                }
                return instance;
            }
        }

        public static Blake2bMac Blake2b_256
        {
            get
            {
                Blake2bMac? instance = s_Blake2b_256;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Blake2b_256, new Blake2bMac(crypto_generichash_blake2b_KEYBYTES, 256 / 8), null);
                    instance = s_Blake2b_256;
                }
                return instance;
            }
        }

        public static Blake2bMac Blake2b_512
        {
            get
            {
                Blake2bMac? instance = s_Blake2b_512;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Blake2b_512, new Blake2bMac(crypto_generichash_blake2b_KEYBYTES, 512 / 8), null);
                    instance = s_Blake2b_512;
                }
                return instance;
            }
        }

        public static HmacSha256 HmacSha256
        {
            get
            {
                HmacSha256? instance = s_HmacSha256;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_HmacSha256, new HmacSha256(crypto_hash_sha256_BYTES, 256 / 8), null);
                    instance = s_HmacSha256;
                }
                return instance;
            }
        }

        public static HmacSha256 HmacSha256_128
        {
            get
            {
                HmacSha256? instance = s_HmacSha256_128;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_HmacSha256_128, new HmacSha256(crypto_hash_sha256_BYTES, 128 / 8), null);
                    instance = s_HmacSha256_128;
                }
                return instance;
            }
        }

        public static HmacSha512 HmacSha512
        {
            get
            {
                HmacSha512? instance = s_HmacSha512;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_HmacSha512, new HmacSha512(crypto_hash_sha512_BYTES, 512 / 8), null);
                    instance = s_HmacSha512;
                }
                return instance;
            }
        }

        public static HmacSha512 HmacSha512_256
        {
            get
            {
                HmacSha512? instance = s_HmacSha512_256;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_HmacSha512_256, new HmacSha512(crypto_hash_sha512_BYTES, 256 / 8), null);
                    instance = s_HmacSha512_256;
                }
                return instance;
            }
        }

        public int KeySize => _keySize;

        public int MacSize => _macSize;

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
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }

            byte[] mac = new byte[_macSize];
            MacCore(key.Span, data, mac);
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
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (mac.Length != _macSize)
            {
                throw Error.Argument_MacLength(nameof(mac), _macSize);
            }

            MacCore(key.Span, data, mac);
        }

        public bool Verify(
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
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }

            return mac.Length == _macSize && VerifyCore(key.Span, data, mac);
        }

        internal abstract bool FinalizeAndVerifyCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> mac);

        internal abstract void FinalizeCore(
            ref IncrementalMacState state,
            Span<byte> mac);

        internal sealed override int GetKeySize()
        {
            return _keySize;
        }

        internal sealed override int GetPublicKeySize()
        {
            throw Error.InvalidOperation_InternalError();
        }

        internal abstract override int GetSeedSize();

        internal abstract void InitializeCore(
            ReadOnlySpan<byte> key,
            out IncrementalMacState state);

        internal abstract void UpdateCore(
            ref IncrementalMacState state,
            ReadOnlySpan<byte> data);

        private protected abstract void MacCore(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> data,
            Span<byte> mac);

        private protected abstract bool VerifyCore(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac);
    }
}
