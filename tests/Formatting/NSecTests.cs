using System;
using System.Text;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Formatting
{
    public static class NSecTests
    {
        [Theory]
        [InlineData(typeof(Aes256Gcm), new byte[] { 0xDE, 0x31, 0x44, 0xDE })]
        [InlineData(typeof(ChaCha20Poly1305), new byte[] { 0xDE, 0x31, 0x43, 0xDE })]
        public static void Aead(Type algorithmType, byte[] blobHeader)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            Test(a, a.KeySize, KeyBlobFormat.RawSymmetricKey, a.KeySize, KeyBlobFormat.NSecSymmetricKey, blobHeader);
        }

        [Theory]
        [InlineData(typeof(Blake2bMac), new byte[] { 0xDE, 0x32, 0x45, 0xDE })]
        [InlineData(typeof(HmacSha256), new byte[] { 0xDE, 0x33, 0x46, 0xDE })]
        [InlineData(typeof(HmacSha512), new byte[] { 0xDE, 0x33, 0x47, 0xDE })]
        public static void Mac(Type algorithmType, byte[] blobHeader)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Test(a, a.DefaultKeySize, KeyBlobFormat.RawSymmetricKey, a.DefaultKeySize, KeyBlobFormat.NSecSymmetricKey, blobHeader);
        }

        [Fact]
        public static void Ed25519Private()
        {
            var a = new Ed25519();

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PrivateKeySize, KeyBlobFormat.NSecPrivateKey, new byte[] { 0xDE, 0x34, 0x42, 0xDE });
        }

        [Fact]
        public static void Ed25519Public()
        {
            var a = new Ed25519();

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PublicKeySize, KeyBlobFormat.NSecPublicKey, new byte[] { 0xDE, 0x35, 0x42, 0xDE });
        }

        [Fact]
        public static void X25519Private()
        {
            var a = new X25519();

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PrivateKeySize, KeyBlobFormat.NSecPrivateKey, new byte[] { 0xDE, 0x36, 0x41, 0xDE });
        }

        [Fact]
        public static void X25519Public()
        {
            var a = new X25519();

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PublicKeySize, KeyBlobFormat.NSecPublicKey, new byte[] { 0xDE, 0x37, 0x41, 0xDE });
        }

        private static void Test(Algorithm a, int seedSize, KeyBlobFormat importFormat, int keySize, KeyBlobFormat format, byte[] blobHeader)
        {
            var b = Utilities.RandomBytes.Slice(0, seedSize);

            using (var k = Key.Import(a, b, importFormat, KeyExportPolicies.AllowPlaintextArchiving))
            {
                var blob = k.Export(format);

                Assert.NotNull(blob);
                Assert.Equal(blobHeader.Length + sizeof(uint) + keySize, blob.Length);
                Assert.Equal(blobHeader, blob.AsSpan(0, blobHeader.Length).ToArray());
                Assert.Equal(BitConverter.GetBytes(keySize), blob.AsSpan(blobHeader.Length, sizeof(int)).ToArray());
            }
        }
    }
}
