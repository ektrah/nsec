using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Formatting
{
    public static class NSecTests
    {
        [Theory]
        [InlineData(typeof(Aes256Gcm), new byte[] { 0x7F, 0x31, 0x44, 0 })]
        [InlineData(typeof(ChaCha20Poly1305), new byte[] { 0x7F, 0x31, 0x43, 0 })]
        public static void TestAead(Type algorithmType, byte[] magic)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            Test(a, a.KeySize, KeyBlobFormat.RawSymmetricKey, a.KeySize, KeyBlobFormat.NSecSymmetricKey, magic);
        }

        [Fact]
        public static void TestBlake2()
        {
            var a = new Blake2();

            Test(a, a.DefaultKeySize, KeyBlobFormat.RawSymmetricKey, a.DefaultKeySize, KeyBlobFormat.NSecSymmetricKey, new byte[] { 0x7F, 0x32, 0x45, 0 });
        }

        [Theory]
        [InlineData(typeof(HmacSha256), new byte[] { 0x7F, 0x33, 0x46, 0 })]
        [InlineData(typeof(HmacSha512), new byte[] { 0x7F, 0x33, 0x47, 0 })]
        public static void TestMac(Type algorithmType, byte[] magic)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Test(a, a.DefaultKeySize, KeyBlobFormat.RawSymmetricKey, a.DefaultKeySize, KeyBlobFormat.NSecSymmetricKey, magic);
        }

        [Fact]
        public static void TestEd25519Private()
        {
            var a = new Ed25519();

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PrivateKeySize, KeyBlobFormat.NSecPrivateKey, new byte[] { 0x7F, 0x34, 0x42, 0 });
        }

        [Fact]
        public static void TestEd25519Public()
        {
            var a = new Ed25519();

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PublicKeySize, KeyBlobFormat.NSecPublicKey, new byte[] { 0x7F, 0x35, 0x42, 0 });
        }

        [Fact]
        public static void TestX25519Private()
        {
            var a = new X25519();

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PrivateKeySize, KeyBlobFormat.NSecPrivateKey, new byte[] { 0x7F, 0x36, 0x41, 0 });
        }

        [Fact]
        public static void TestX25519Public()
        {
            var a = new X25519();

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PublicKeySize, KeyBlobFormat.NSecPublicKey, new byte[] { 0x7F, 0x37, 0x41, 0 });
        }

        private static void Test(Algorithm a, int seedSize, KeyBlobFormat importFormat, int keySize, KeyBlobFormat format, byte[] magic)
        {
            var b = Utilities.RandomBytes.Slice(0, seedSize);

            using (var k = Key.Import(a, b, importFormat, KeyFlags.AllowArchiving))
            {
                var blob = new ReadOnlySpan<byte>(k.Export(format));

                Assert.NotNull(blob);
                Assert.Equal(magic.Length + sizeof(uint) + keySize, blob.Length);
                Assert.Equal(magic, blob.Slice(0, magic.Length).ToArray());
                Assert.Equal(BitConverter.GetBytes(keySize), blob.Slice(magic.Length, sizeof(int)).ToArray());
            }
        }
    }
}
