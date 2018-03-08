using System;
using System.Diagnostics;
using NSec.Cryptography;
using Xunit;

namespace Examples.Nonces
{
    public enum Role
    {
        Server,
        Client,
    }

    #region Nonces: RFC 5288

    public class Rfc5288
    {
        private readonly AeadAlgorithm _algorithm;
        private readonly Key _readKey;
        private readonly Key _writeKey;

        private Nonce _readNonce;
        private Nonce _writeNonce;

        public Rfc5288(
            Role role,
            AeadAlgorithm algorithm,
            Key clientWriteKey, ReadOnlySpan<byte> clientWriteIV,
            Key serverWriteKey, ReadOnlySpan<byte> serverWriteIV)
        {
            Debug.Assert(algorithm.NonceSize == 12);
            Debug.Assert(clientWriteIV.Length == 4);
            Debug.Assert(serverWriteIV.Length == 4);

            switch (role)
            {
            case Role.Server:
                _algorithm = algorithm;
                _writeKey = serverWriteKey;
                _writeNonce = new Nonce(serverWriteIV, 8);
                _readKey = clientWriteKey;
                _readNonce = new Nonce(clientWriteIV, 8);
                break;

            case Role.Client:
                _algorithm = algorithm;
                _writeKey = clientWriteKey;
                _writeNonce = new Nonce(clientWriteIV, 8);
                _readKey = serverWriteKey;
                _readNonce = new Nonce(serverWriteIV, 8);
                break;

            default:
                break;
            }
        }

        public void Read(
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            _algorithm.Decrypt(
                _readKey,
                _readNonce,
                associatedData,
                ciphertext,
                plaintext);

            _readNonce++;
        }

        public void Write(
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            _algorithm.Encrypt(
                _writeKey,
                _writeNonce,
                associatedData,
                plaintext,
                ciphertext);

            _writeNonce++;
        }
    }

    #endregion

    #region Nonces: RFC 7905

    public class Rfc7905
    {
        private readonly AeadAlgorithm _algorithm;
        private readonly Nonce _readIV;
        private readonly Key _readKey;
        private readonly Nonce _writeIV;
        private readonly Key _writeKey;

        private Nonce _readNonce;
        private Nonce _writeNonce;

        public Rfc7905(
            Role role,
            AeadAlgorithm algorithm,
            Key clientWriteKey, ReadOnlySpan<byte> clientWriteIV,
            Key serverWriteKey, ReadOnlySpan<byte> serverWriteIV)
        {
            Debug.Assert(algorithm.NonceSize >= 8);
            Debug.Assert(clientWriteIV.Length == algorithm.NonceSize);
            Debug.Assert(serverWriteIV.Length == algorithm.NonceSize);

            switch (role)
            {
            case Role.Server:
                _algorithm = algorithm;
                _writeKey = serverWriteKey;
                _writeIV = new Nonce(serverWriteIV, 0);
                _writeNonce = new Nonce(algorithm.NonceSize - 8, 8);
                _readKey = clientWriteKey;
                _readIV = new Nonce(clientWriteIV, 0);
                _readNonce = new Nonce(algorithm.NonceSize - 8, 8);
                break;

            case Role.Client:
                _algorithm = algorithm;
                _writeKey = clientWriteKey;
                _writeIV = new Nonce(clientWriteIV, 0);
                _writeNonce = new Nonce(algorithm.NonceSize - 8, 8);
                _readKey = serverWriteKey;
                _readIV = new Nonce(serverWriteIV, 0);
                _readNonce = new Nonce(algorithm.NonceSize - 8, 8);
                break;

            default:
                throw new ArgumentException();
            }
        }

        public void Read(
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            _algorithm.Decrypt(
                _readKey,
                _readNonce ^ _readIV,
                associatedData,
                ciphertext,
                plaintext);

            _readNonce++;
        }

        public void Write(
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            _algorithm.Encrypt(
                _writeKey,
                _writeNonce ^ _writeIV,
                associatedData,
                plaintext,
                ciphertext);

            _writeNonce++;
        }
    }

    #endregion

    public static class Tests
    {
        [Fact]
        public static void Rfc5288()
        {
            var algorithm = new Aes256Gcm();

            using (var clientWriteKey = new Key(algorithm))
            using (var serverWriteKey = new Key(algorithm))
            {
                var clientWriteIV = new byte[] { 0x38, 0x71, 0xd4, 0x13 };
                var serverWriteIV = new byte[] { 0x59, 0xf2, 0xcd, 0x8a };

                var client = new Rfc5288(Role.Client, algorithm, clientWriteKey, clientWriteIV, serverWriteKey, serverWriteIV);
                var server = new Rfc5288(Role.Server, algorithm, clientWriteKey, clientWriteIV, serverWriteKey, serverWriteIV);

                var associatedData = new byte[] { 0x58, 0xbf, 0x8f, 0x3e, 0xfa, 0x04 };
                var expected = new byte[] { 0x59, 0x3d, 0x8a, 0x16, 0x03, 0x10, 0x32, 0xfb, 0x06, 0x20 };
                var actual = new byte[expected.Length];
                var ciphertext = new byte[expected.Length + algorithm.TagSize];

                for (var i = 0; i < 10; i++)
                {
                    client.Write(associatedData, expected, ciphertext);
                    server.Read(associatedData, ciphertext, actual);

                    Assert.Equal(expected, actual);
                }
            }
        }

        [Fact]
        public static void Rfc7905()
        {
            var algorithm = new ChaCha20Poly1305();

            using (var clientWriteKey = new Key(algorithm))
            using (var serverWriteKey = new Key(algorithm))
            {
                var clientWriteIV = new byte[] { 0xb0, 0x34, 0xd7, 0x53, 0x89, 0x60, 0x09, 0xf9, 0x2d, 0xe9, 0xe6, 0x02 };
                var serverWriteIV = new byte[] { 0x12, 0xb3, 0x0a, 0x46, 0x36, 0x7d, 0x6d, 0x5d, 0xb1, 0xce, 0xb8, 0x57 };

                var client = new Rfc7905(Role.Client, algorithm, clientWriteKey, clientWriteIV, serverWriteKey, serverWriteIV);
                var server = new Rfc7905(Role.Server, algorithm, clientWriteKey, clientWriteIV, serverWriteKey, serverWriteIV);

                var associatedData = new byte[] { 0x60, 0x41, 0xe2, 0xbf, 0x3c };
                var expected = new byte[] { 0xbc, 0x20, 0x96, 0xcd, 0x46, 0xbe, 0x9a, 0x63, 0x61, 0xde };
                var actual = new byte[expected.Length];
                var ciphertext = new byte[expected.Length + algorithm.TagSize];

                for (var i = 0; i < 10; i++)
                {
                    client.Write(associatedData, expected, ciphertext);
                    server.Read(associatedData, ciphertext, actual);

                    Assert.Equal(expected, actual);
                }
            }
        }
    }
}
