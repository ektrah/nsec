using System;
using System.Diagnostics;
using System.Threading;

namespace NSec.Cryptography
{
    //
    //  A cryptographic hash algorithm
    //
    //  Candidates
    //
    //      | Algorithm | Reference       | Customization | Hash Size |
    //      | --------- | --------------- | ------------- | --------- |
    //      | BLAKE2b   | RFC 7693        | no            | 1..64     |
    //      | SHA-256   | RFC 6234        | no            | 32        |
    //      | SHA-512   | RFC 6234        | no            | 64        |
    //      | SHA3-256  | NIST FIPS 202   | no            | 32        |
    //      | SHA3-512  | NIST FIPS 202   | no            | 64        |
    //      | SHAKE128  | NIST FIPS 202   | no            | any       |
    //      | SHAKE256  | NIST FIPS 202   | no            | any       |
    //      | cSHAKE128 | NIST SP 800-185 | yes           | any       |
    //      | cSHAKE256 | NIST SP 800-185 | yes           | any       |
    //
    public abstract class HashAlgorithm : Algorithm
    {
        private static Blake2b s_Blake2b;
        private static Sha256 s_Sha256;
        private static Sha512 s_Sha512;

        private readonly int _hashSize;

        private protected HashAlgorithm(
            int hashSize)
        {
            Debug.Assert(hashSize > 0);

            _hashSize = hashSize;
        }

        public static Blake2b Blake2b
        {
            get
            {
                Blake2b instance = s_Blake2b;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Blake2b, new Blake2b(), null);
                    instance = s_Blake2b;
                }
                return instance;
            }
        }

        public static Sha256 Sha256
        {
            get
            {
                Sha256 instance = s_Sha256;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Sha256, new Sha256(), null);
                    instance = s_Sha256;
                }
                return instance;
            }
        }

        public static Sha512 Sha512
        {
            get
            {
                Sha512 instance = s_Sha512;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_Sha512, new Sha512(), null);
                    instance = s_Sha512;
                }
                return instance;
            }
        }

        public int HashSize => _hashSize;

        public byte[] Hash(
            ReadOnlySpan<byte> data)
        {
            byte[] hash = new byte[_hashSize];
            HashCore(data, hash);
            return hash;
        }

        public void Hash(
            ReadOnlySpan<byte> data,
            Span<byte> hash)
        {
            if (hash.Length != _hashSize)
            {
                throw Error.Argument_HashLength(nameof(hash), _hashSize.ToString());
            }

            HashCore(data, hash);
        }

        public bool TryVerify(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash)
        {
            return hash.Length == _hashSize && TryVerifyCore(data, hash);
        }

        public void Verify(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash)
        {
            if (!(hash.Length == _hashSize && TryVerifyCore(data, hash)))
            {
                throw Error.Cryptographic_VerificationFailed();
            }
        }

        internal abstract bool FinalizeAndTryVerifyCore(
            ref IncrementalHash.State state,
            ReadOnlySpan<byte> hash);

        internal abstract void FinalizeCore(
            ref IncrementalHash.State state,
            Span<byte> hash);

        internal abstract void InitializeCore(
            int hashSize,
            out IncrementalHash.State state);

        internal abstract void UpdateCore(
            ref IncrementalHash.State state,
            ReadOnlySpan<byte> data);

        private protected abstract void HashCore(
            ReadOnlySpan<byte> data,
            Span<byte> hash);

        private protected abstract bool TryVerifyCore(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> hash);
    }
}
