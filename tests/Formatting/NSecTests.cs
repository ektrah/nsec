using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Formatting
{
    public static class NSecTests
    {
        [Theory]
        [InlineData(typeof(Aes256Gcm), new byte[] { 0xDE, 0x61, 0x44, 0xDE })]
        [InlineData(typeof(ChaCha20Poly1305), new byte[] { 0xDE, 0x61, 0x43, 0xDE })]
        public static void Aead(Type algorithmType, byte[] blobHeader)
        {
            var a = (AeadAlgorithm)(Activator.CreateInstance(algorithmType) ?? throw new NullReferenceException());

            Test(a, a.KeySize, KeyBlobFormat.RawSymmetricKey, a.KeySize, a.TagSize, KeyBlobFormat.NSecSymmetricKey, blobHeader);
        }

        [Theory]
        [InlineData(typeof(Blake2bMac), new byte[] { 0xDE, 0x62, 0x45, 0xDE })]
        [InlineData(typeof(HmacSha256), new byte[] { 0xDE, 0x63, 0x46, 0xDE })]
        [InlineData(typeof(HmacSha512), new byte[] { 0xDE, 0x63, 0x47, 0xDE })]
        public static void Mac(Type algorithmType, byte[] blobHeader)
        {
            var a = (MacAlgorithm)(Activator.CreateInstance(algorithmType) ?? throw new NullReferenceException());

            Test(a, a.KeySize, KeyBlobFormat.RawSymmetricKey, a.KeySize, a.MacSize, KeyBlobFormat.NSecSymmetricKey, blobHeader);
        }

        [Fact]
        public static void Ed25519Private()
        {
            var a = SignatureAlgorithm.Ed25519;

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PrivateKeySize, a.SignatureSize, KeyBlobFormat.NSecPrivateKey, new byte[] { 0xDE, 0x64, 0x42, 0xDE });
        }

        [Fact]
        public static void Ed25519Public()
        {
            var a = SignatureAlgorithm.Ed25519;

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PublicKeySize, a.SignatureSize, KeyBlobFormat.NSecPublicKey, new byte[] { 0xDE, 0x65, 0x42, 0xDE });
        }

        [Fact]
        public static void X25519Private()
        {
            var a = KeyAgreementAlgorithm.X25519;

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PrivateKeySize, a.SharedSecretSize, KeyBlobFormat.NSecPrivateKey, new byte[] { 0xDE, 0x66, 0x41, 0xDE });
        }

        [Fact]
        public static void X25519Public()
        {
            var a = KeyAgreementAlgorithm.X25519;

            Test(a, a.PrivateKeySize, KeyBlobFormat.RawPrivateKey, a.PublicKeySize, a.SharedSecretSize, KeyBlobFormat.NSecPublicKey, new byte[] { 0xDE, 0x67, 0x41, 0xDE });
        }

        private static void Test(Algorithm a, int seedSize, KeyBlobFormat importFormat, int keySize, int outputSize, KeyBlobFormat format, byte[] blobHeader)
        {
            var b = Utilities.RandomBytes.Slice(0, seedSize);

            using var k = Key.Import(a, b, importFormat, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });

            var blob = k.Export(format);

            Assert.NotNull(blob);
            Assert.Equal(blobHeader.Length + sizeof(short) + sizeof(short) + keySize, blob.Length);
            Assert.Equal(blobHeader, blob.AsSpan(0, blobHeader.Length).ToArray());
            Assert.Equal(keySize, BitConverter.ToInt16(blob, blobHeader.Length));
            Assert.Equal(outputSize, BitConverter.ToInt16(blob, blobHeader.Length + sizeof(short)));
        }
    }
}
