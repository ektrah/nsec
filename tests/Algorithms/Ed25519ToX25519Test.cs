using System;
using System.Linq;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public class Ed25519ToX25519Test
    {
        [Fact]
        public void TestEd25519_to_X25519()
        {
            var ed25519 = Key.Create(SignatureAlgorithm.Ed25519,
                new KeyCreationParameters() {ExportPolicy = KeyExportPolicies.AllowPlaintextExport});
            var x25519pub = Ed25519ToX25519.SignEd25519PublicToCurve25519(ed25519.PublicKey);
            var x25519priv = Ed25519ToX25519.SignEd25519SecretToCurve25519(ed25519);
            Assert.Equal(x25519priv.PublicKey, x25519pub);
            //Additional tests needed! this just checks that the key returned is valid.
        }

        public static byte[] FromHex(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public static string ToHex(byte[] data)
        {
            if (data == null)
            {
                return String.Empty;
            }

            string hex = BitConverter.ToString(data);
            return hex.Replace("-", "").ToLower();
        }
    }
}
