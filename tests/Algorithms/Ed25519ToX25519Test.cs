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
            var ed25519Public = FromHex("8fbe438aab6c40dc2ebc839ba27530ca1bf23d4efd36958a3365406efe52ccd1");
            var ed25519Private =
                FromHex(
                    "28e9e1d48cb0e52e437080e4a180058d7a42a07abcd05ea2ec4e6122cded8f6a0d2a6b9fd1878fd76ab20caecab666916ac3cc772fc57f8fa6e8dc3227bb8497");

            var expectedPublic = FromHex("26100e941bdd2103038d8dec9a1884694736f591ee814e66ae6e2e2284757136");
            var expectedPrivate = FromHex("803fcdab44e9958d2f8e4d47b5f0d481d6ddb79dd462a18ee65cabe94a9e455c");

            var x25519Public = Ed25519ToX25519.SignEd25519PublicToCurve25519(ed25519Public);
            var x25519Secret = Ed25519ToX25519.SignEd25519SecretToCurve25519(ed25519Private);

            Assert.Equal(expectedPublic, x25519Public);
            Assert.Equal(expectedPrivate, x25519Secret);
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
