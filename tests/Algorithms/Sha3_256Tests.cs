using System;
using NSec.Cryptography.Experimental;
using Xunit;

namespace NSec.Tests.Algorithms
{
    public static class Sha3_256Tests
    {
        private static readonly string s_hashOfEmpty = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

        #region Properties

        [Fact]
        public static void Properties()
        {
            var a = new Sha3_256();

            Assert.Equal(32, a.MinHashSize);
            Assert.Equal(32, a.DefaultHashSize);
            Assert.Equal(32, a.MaxHashSize);
        }

        #endregion

        #region Hash #1

        [Fact]
        public static void HashEmpty()
        {
            var a = new Sha3_256();

            var expected = s_hashOfEmpty.DecodeHex();
            var actual = a.Hash(ReadOnlySpan<byte>.Empty);

            Assert.Equal(a.DefaultHashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        #endregion

        #region Hash #2

        [Fact]
        public static void HashEmptyWithSize()
        {
            var a = new Sha3_256();

            var expected = s_hashOfEmpty.DecodeHex();
            var actual = a.Hash(ReadOnlySpan<byte>.Empty, a.MaxHashSize);

            Assert.Equal(a.MaxHashSize, actual.Length);
            Assert.Equal(expected, actual);
        }

        #endregion

        #region Hash #3

        [Fact]
        public static void HashEmptyWithSpan()
        {
            var a = new Sha3_256();

            var expected = s_hashOfEmpty.DecodeHex();
            var actual = new byte[expected.Length];

            a.Hash(ReadOnlySpan<byte>.Empty, actual);
            Assert.Equal(expected, actual);
        }

        #endregion
    }
}
