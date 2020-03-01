using System;
using System.Text;
using NSec.Cryptography;
using NSec.Experimental.Asn1;
using Xunit;

namespace NSec.Tests.Formatting
{
    public static class Ed25519Tests
    {
        private static readonly byte[] s_oid = new Asn1Oid(1, 3, 101, 112).Bytes.ToArray();

        [Fact]
        public static void PkixPrivateKey()
        {
            var a = SignatureAlgorithm.Ed25519;
            var b = Utilities.RandomBytes.Slice(0, a.PrivateKeySize);

            using var k = Key.Import(a, b, KeyBlobFormat.RawPrivateKey, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var blob = k.Export(KeyBlobFormat.PkixPrivateKey);

            var reader = new Asn1Reader(blob);
            reader.BeginSequence();
            Assert.Equal(0, reader.Integer32());
            reader.BeginSequence();
            Assert.Equal(s_oid, reader.ObjectIdentifier().ToArray());
            reader.End();
            var curvePrivateKey = new Asn1Reader(reader.OctetString());
            Assert.Equal(b.ToArray(), curvePrivateKey.OctetString().ToArray());
            Assert.True(curvePrivateKey.SuccessComplete);
            reader.End();
            Assert.True(reader.SuccessComplete);
        }

        [Fact]
        public static void PkixPrivateKeyText()
        {
            var a = SignatureAlgorithm.Ed25519;
            var b = Utilities.RandomBytes.Slice(0, a.PrivateKeySize);

            using var k = Key.Import(a, b, KeyBlobFormat.RawPrivateKey, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var expected = Encoding.UTF8.GetBytes(
                "-----BEGIN PRIVATE KEY-----\r\n" +
                Convert.ToBase64String(k.Export(KeyBlobFormat.PkixPrivateKey)) + "\r\n" +
                "-----END PRIVATE KEY-----\r\n");

            var actual = k.Export(KeyBlobFormat.PkixPrivateKeyText);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public static void PkixPublicKey()
        {
            var a = SignatureAlgorithm.Ed25519;
            var b = Utilities.RandomBytes.Slice(0, a.PrivateKeySize);

            using var k = Key.Import(a, b, KeyBlobFormat.RawPrivateKey);
            var publicKeyBytes = k.Export(KeyBlobFormat.RawPublicKey);
            var blob = k.Export(KeyBlobFormat.PkixPublicKey);

            var reader = new Asn1Reader(blob);
            reader.BeginSequence();
            reader.BeginSequence();
            Assert.Equal(s_oid, reader.ObjectIdentifier().ToArray());
            reader.End();
            Assert.Equal(publicKeyBytes, reader.BitString().ToArray());
            reader.End();
            Assert.True(reader.SuccessComplete);
        }

        [Fact]
        public static void PkixPublicKeyText()
        {
            var a = SignatureAlgorithm.Ed25519;
            var b = Utilities.RandomBytes.Slice(0, a.PrivateKeySize);

            using var k = Key.Import(a, b, KeyBlobFormat.RawPrivateKey);
            var expected = Encoding.UTF8.GetBytes(
                "-----BEGIN PUBLIC KEY-----\r\n" +
                Convert.ToBase64String(k.Export(KeyBlobFormat.PkixPublicKey)) + "\r\n" +
                "-----END PUBLIC KEY-----\r\n");

            var actual = k.Export(KeyBlobFormat.PkixPublicKeyText);

            Assert.Equal(expected, actual);
        }
    }
}
