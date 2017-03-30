using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Sha256Tests
    {
        private static readonly string s_hashOfEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        [Fact]
        public static void Properties2()
        {
            var a = new Sha256();

            Assert.Equal(32, a.MinHashSize);
            Assert.Equal(32, a.DefaultHashSize);
            Assert.Equal(32, a.MaxHashSize);
        }

        [Fact]
        public static void HashEmpty()
        {
            var a = new Sha256();

            var expected = s_hashOfEmpty.DecodeHex();
            var actual = a.Hash(ReadOnlySpan<byte>.Empty);

            Assert.Equal(a.DefaultHashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public static void HashEmptyWithSize()
        {
            var a = new Sha256();

            var expected = s_hashOfEmpty.DecodeHex();
            var actual = a.Hash(ReadOnlySpan<byte>.Empty, a.MaxHashSize);

            Assert.Equal(a.MaxHashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public static void HashEmptyWithSpan()
        {
            var a = new Sha256();

            var expected = s_hashOfEmpty.DecodeHex();
            var actual = new byte[expected.Length];

            a.Hash(ReadOnlySpan<byte>.Empty, actual);
            Assert.Equal(expected, actual);
        }
    }
}
