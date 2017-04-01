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
        public static void TestAead(Type algorithmType, byte[] magic)
        {
            var a = (AeadAlgorithm)Activator.CreateInstance(algorithmType);

            Test(a, a.KeySize, KeyBlobFormat.RawSymmetricKey, a.KeySize, KeyBlobFormat.NSecSymmetricKey, magic);
        }

        [Fact]
        public static void TestBlake2()
        {
            var a = new Blake2();

            Test(a, a.DefaultKeySize, KeyBlobFormat.RawSymmetricKey, a.DefaultKeySize, KeyBlobFormat.NSecSymmetricKey, new byte[] { 0xDE, 0x32, 0x45, 0xDE });
        }

        [Theory]
        [InlineData(typeof(HmacSha256), new byte[] { 0xDE, 0x33, 0x46, 0xDE })]
        [InlineData(typeof(HmacSha512), new byte[] { 0xDE, 0x33, 0x47, 0xDE })]
        public static void TestMac(Type algorithmType, byte[] magic)
        {
            var a = (MacAlgorithm)Activator.CreateInstance(algorithmType);

            Test(a, a.DefaultKeySize, KeyBlobFormat.RawSymmetricKey, a.DefaultKeySize, KeyBlobFormat.NSecSymmetricKey, magic);
        }

        [Fact]
        public static void TestEd25519Private()
        {
            var a = new Ed25519();

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PrivateKeySize, KeyBlobFormat.NSecPrivateKey, new byte[] { 0xDE, 0x34, 0x42, 0xDE });
        }

        [Fact]
        public static void TestEd25519Public()
        {
            var a = new Ed25519();

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PublicKeySize, KeyBlobFormat.NSecPublicKey, new byte[] { 0xDE, 0x35, 0x42, 0xDE });
        }

        [Fact]
        public static void TestX25519Private()
        {
            var a = new X25519();

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PrivateKeySize, KeyBlobFormat.NSecPrivateKey, new byte[] { 0xDE, 0x36, 0x41, 0xDE });
        }

        [Fact]
        public static void TestX25519Public()
        {
            var a = new X25519();

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PublicKeySize, KeyBlobFormat.NSecPublicKey, new byte[] { 0xDE, 0x37, 0x41, 0xDE });
        }

        [Fact]
        public static void BlobHeader()
        {
            for (var i = 0; i < 128; i++)
            {
                for (var j = 0; j < 128; j++)
                {
                    var b = new byte[] { 0xDE, (byte)i, (byte)j, 0xDE, 0, 0, 0, 0 };

                    Assert.Throws<DecoderFallbackException>(() => new UTF8Encoding(false, true).GetString(b));
                    Assert.Throws<DecoderFallbackException>(() => new UnicodeEncoding(true, false, true).GetString(b));
                    Assert.Throws<DecoderFallbackException>(() => new UnicodeEncoding(false, false, true).GetString(b));
                    Assert.Throws<DecoderFallbackException>(() => new UTF32Encoding(true, false, true).GetString(b));
                    Assert.Throws<DecoderFallbackException>(() => new UTF32Encoding(false, false, true).GetString(b));
                }
            }
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
