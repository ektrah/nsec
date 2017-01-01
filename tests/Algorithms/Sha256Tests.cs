using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Sha256Tests
    {
        public static readonly string HashOfEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        [Fact]
        public static void HashEmpty()
        {
            var a = new Sha256();

            var expected = HashOfEmpty.DecodeHex();
            var actual = a.Hash(ReadOnlySpan<byte>.Empty);

            Assert.Equal(a.DefaultHashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(16)]
        [InlineData(17)]
        [InlineData(23)]
        [InlineData(31)]
        [InlineData(32)]
        public static void HashEmptyWithSize(int hashSize)
        {
            var a = new Sha256();

            var expected = HashOfEmpty.DecodeHex().Substring(0, hashSize);
            var actual = a.Hash(ReadOnlySpan<byte>.Empty, hashSize);

            Assert.Equal(hashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(16)]
        [InlineData(17)]
        [InlineData(23)]
        [InlineData(31)]
        [InlineData(32)]
        public static void HashEmptyWithSpan(int hashSize)
        {
            var a = new Sha256();

            var expected = HashOfEmpty.DecodeHex().Substring(0, hashSize);
            var actual = new byte[hashSize];

            a.Hash(ReadOnlySpan<byte>.Empty, actual);
            Assert.Equal(expected, actual);
        }
    }
}
