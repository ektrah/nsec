using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Sha512Tests
    {
        private static readonly string s_hashOfEmpty = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

        [Fact]
        public static void Properties()
        {
            var a = new Sha512();

            Assert.Equal(32, a.MinHashSize);
            Assert.Equal(64, a.DefaultHashSize);
            Assert.Equal(64, a.MaxHashSize);
        }

        [Fact]
        public static void HashEmpty()
        {
            var a = new Sha512();

            var expected = s_hashOfEmpty.DecodeHex();
            var actual = a.Hash(ReadOnlySpan<byte>.Empty);

            Assert.Equal(a.DefaultHashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(32)]
        [InlineData(41)]
        [InlineData(53)]
        [InlineData(61)]
        [InlineData(64)]
        public static void HashEmptyWithSize(int hashSize)
        {
            var a = new Sha512();

            var expected = s_hashOfEmpty.DecodeHex().Substring(0, hashSize);
            var actual = a.Hash(ReadOnlySpan<byte>.Empty, hashSize);

            Assert.Equal(hashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(32)]
        [InlineData(41)]
        [InlineData(53)]
        [InlineData(61)]
        [InlineData(64)]
        public static void HashEmptyWithSpan(int hashSize)
        {
            var a = new Sha512();

            var expected = s_hashOfEmpty.DecodeHex().Substring(0, hashSize);
            var actual = new byte[hashSize];

            a.Hash(ReadOnlySpan<byte>.Empty, actual);
            Assert.Equal(expected, actual);
        }
    }
}
