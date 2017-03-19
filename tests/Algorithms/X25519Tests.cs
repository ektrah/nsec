using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class X25519Tests
    {
        [Fact]
        public static void BitMasked()
        {
            var a = new X25519();
            var kdf = new HkdfSha256();

            using (var kA = new Key(a))
            using (var kB = new Key(a))
            {
                var pk1 = kB.Export(KeyBlobFormat.RawPublicKey);
                var pk2 = kB.Export(KeyBlobFormat.RawPublicKey);

                pk1[pk1.Length - 1] &= 0x7F;
                pk2[pk2.Length - 1] |= 0x80;

                using (var s1 = a.Agree(kA, PublicKey.Import(a, pk1, KeyBlobFormat.RawPublicKey)))
                using (var s2 = a.Agree(kA, PublicKey.Import(a, pk2, KeyBlobFormat.RawPublicKey)))
                {
                    var b1 = kdf.Extract(s1, ReadOnlySpan<byte>.Empty);
                    var b2 = kdf.Extract(s2, ReadOnlySpan<byte>.Empty);

                    Assert.Equal(b1, b2);
                }
            }
        }

        [Fact]
        public static void BitMaskedEqual()
        {
            var a = new X25519();

            var pk1 = Utilities.RandomBytes.Slice(0, a.PublicKeySize).ToArray();
            var pk2 = Utilities.RandomBytes.Slice(0, a.PublicKeySize).ToArray();

            pk1[pk1.Length - 1] &= 0x7F;
            pk2[pk2.Length - 1] |= 0x80;

            var p1 = PublicKey.Import(a, pk1, KeyBlobFormat.RawPublicKey);
            var p2 = PublicKey.Import(a, pk2, KeyBlobFormat.RawPublicKey);

            Assert.True(p1.Equals(p2));
        }
    }
}
