using System;
using System.Diagnostics;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Examples
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

        private readonly Key _sendKey;
        private Nonce _sendNonce;

        private readonly Key _receiveKey;
        private Nonce _receiveNonce;

        public Rfc5288(
            Role role,
            AeadAlgorithm algorithm,
            Key clientWriteKey,
            ReadOnlySpan<byte> clientWriteIV,
            Key serverWriteKey,
            ReadOnlySpan<byte> serverWriteIV)
        {
            Debug.Assert(algorithm.NonceSize == 12);
            Debug.Assert(clientWriteIV.Length == 4);
            Debug.Assert(serverWriteIV.Length == 4);

            _algorithm = algorithm;

            switch (role)
            {
            // if this is the server side, use serverWriteKey and
            // serverWriteIV for sending, and clientWriteKey and
            // clientWriteIV for receiving
            case Role.Server:
                _sendKey = serverWriteKey;
                _sendNonce = new Nonce(fixedField: serverWriteIV,
                                       counterFieldSize: 8);

                _receiveKey = clientWriteKey;
                _receiveNonce = new Nonce(fixedField: clientWriteIV,
                                          counterFieldSize: 8);
                break;

            // if this is the client side, use clientWriteKey and
            // clientWriteIV for sending, and serverWriteKey and
            // serverWriteIV for receiving
            case Role.Client:
                _sendKey = clientWriteKey;
                _sendNonce = new Nonce(fixedField: clientWriteIV,
                                       counterFieldSize: 8);

                _receiveKey = serverWriteKey;
                _receiveNonce = new Nonce(fixedField: serverWriteIV,
                                          counterFieldSize: 8);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(role));
            }
        }

        public void EncryptBeforeSend(
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            // encrypt the plaintext with the send nonce
            _algorithm.Encrypt(
                _sendKey,
                _sendNonce,
                associatedData,
                plaintext,
                ciphertext);

            // increment the counter field of the send nonce
            if (!Nonce.TryIncrement(ref _sendNonce))
            {
                // abort the connection when the counter field of the
                // send nonce reaches the maximum value
                _sendKey.Dispose();
                _receiveKey.Dispose();
            }
        }

        public bool DecryptAfterReceive(
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            // decrypt the ciphertext with the receive nonce
            if (!_algorithm.Decrypt(
                _receiveKey,
                _receiveNonce,
                associatedData,
                ciphertext,
                plaintext))
            {
                // abort the connection if decryption fails
                _sendKey.Dispose();
                _receiveKey.Dispose();
                return false;
            }

            // increment the counter field of the receive nonce
            if (!Nonce.TryIncrement(ref _receiveNonce))
            {
                // abort the connection when the counter field of the
                // receive nonce reaches the maximum value
                _sendKey.Dispose();
                _receiveKey.Dispose();
            }

            return true;
        }
    }

    #endregion

    #region Nonces: RFC 7905

    public class Rfc7905
    {
        private readonly AeadAlgorithm _algorithm;

        private readonly Key _sendKey;
        private readonly Nonce _sendIV;
        private Nonce _sendSequenceNumber;

        private readonly Key _receiveKey;
        private readonly Nonce _receiveIV;
        private Nonce _receiveSequenceNumber;

        public Rfc7905(
            Role role,
            AeadAlgorithm algorithm,
            Key clientWriteKey,
            ReadOnlySpan<byte> clientWriteIV,
            Key serverWriteKey,
            ReadOnlySpan<byte> serverWriteIV)
        {
            Debug.Assert(algorithm.NonceSize == 12);
            Debug.Assert(clientWriteIV.Length == 12);
            Debug.Assert(serverWriteIV.Length == 12);

            _algorithm = algorithm;

            switch (role)
            {
            // if this is the server side, use serverWriteKey and
            // serverWriteIV for sending, and clientWriteKey and
            // clientWriteIV for receiving
            case Role.Server:
                _sendKey = serverWriteKey;
                _sendIV = new Nonce(fixedField: serverWriteIV,
                                    counterFieldSize: 0);
                _sendSequenceNumber = new Nonce(fixedFieldSize: 4,
                                                counterFieldSize: 8);

                _receiveKey = clientWriteKey;
                _receiveIV = new Nonce(fixedField: clientWriteIV,
                                       counterFieldSize: 0);
                _receiveSequenceNumber = new Nonce(fixedFieldSize: 4,
                                                   counterFieldSize: 8);
                break;

            // if this is the client side, use clientWriteKey and
            // clientWriteIV for sending, and serverWriteKey and
            // serverWriteIV for receiving
            case Role.Client:
                _sendKey = clientWriteKey;
                _sendIV = new Nonce(fixedField: clientWriteIV,
                                    counterFieldSize: 0);
                _sendSequenceNumber = new Nonce(fixedFieldSize: 4,
                                                counterFieldSize: 8);

                _receiveKey = serverWriteKey;
                _receiveIV = new Nonce(fixedField: serverWriteIV,
                                       counterFieldSize: 0);
                _receiveSequenceNumber = new Nonce(fixedFieldSize: 4,
                                                   counterFieldSize: 8);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(role));
            }
        }

        public void EncryptBeforeSend(
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            // encrypt the plaintext with the send sequence number XORed
            // with the send IV as the nonce
            _algorithm.Encrypt(
                _sendKey,
                _sendSequenceNumber ^ _sendIV,
                associatedData,
                plaintext,
                ciphertext);

            // increment the send sequence number
            if (!Nonce.TryIncrement(ref _sendSequenceNumber))
            {
                // abort the connection when the send sequence number
                // reaches the maximum value
                _sendKey.Dispose();
                _receiveKey.Dispose();
            }
        }

        public bool DecryptAfterReceive(
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            // decrypt the ciphertext with the receive sequence number
            // XORed with the receive IV as the nonce
            if (!_algorithm.Decrypt(
                _receiveKey,
                _receiveSequenceNumber ^ _receiveIV,
                associatedData,
                ciphertext,
                plaintext))
            {
                // abort the connection if decryption fails
                _sendKey.Dispose();
                _receiveKey.Dispose();
                return false;
            }

            // increment the receive sequence number
            if (!Nonce.TryIncrement(ref _receiveSequenceNumber))
            {
                // abort the connection when the receive sequence number
                // reaches the maximum value
                _sendKey.Dispose();
                _receiveKey.Dispose();
            }

            return true;
        }
    }

    #endregion

    public static class Nonces
    {
        [Fact]
        public static void Rfc5288()
        {
            var algorithm = AeadAlgorithm.Aes256Gcm;

            using var clientWriteKey = Key.Create(algorithm);
            using var serverWriteKey = Key.Create(algorithm);

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
                client.EncryptBeforeSend(associatedData, expected, ciphertext);
                Assert.True(server.DecryptAfterReceive(associatedData, ciphertext, actual));
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public static void Rfc7905()
        {
            var algorithm = AeadAlgorithm.ChaCha20Poly1305;

            using var clientWriteKey = Key.Create(algorithm);
            using var serverWriteKey = Key.Create(algorithm);

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
                client.EncryptBeforeSend(associatedData, expected, ciphertext);
                Assert.True(server.DecryptAfterReceive(associatedData, ciphertext, actual));
                Assert.Equal(expected, actual);
            }
        }
    }
}
