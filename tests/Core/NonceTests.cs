using System;
using NSec.Cryptography;
using NSec.Cryptography.Formatting;
using Xunit;

namespace NSec.Tests.Core
{
    public static class NonceTests
    {
        public static readonly TheoryData<int> Sizes = GetSizes();

        #region Constants

        private static TheoryData<int> GetSizes()
        {
            var sizes = new TheoryData<int>();
            for (var i = 0; i <= Nonce.MaxSize; i++)
            {
                sizes.Add(i);
            }
            return sizes;
        }

        [Fact]
        public static void Constants()
        {
            Assert.InRange(Nonce.MaxSize, 0x0, 0xF);
        }

        #endregion

        #region Ctor #1

        [Fact]
        public static void Ctor()
        {
            var expected = new byte[0];
            var actual = new Nonce();
            var array = new byte[expected.Length];

            Assert.Equal(expected.Length, actual.Size);
            Assert.Equal(0, actual.FixedFieldSize);
            Assert.Equal(expected.Length, actual.CounterFieldSize);
            Assert.Equal(expected, actual.ToArray());
            Assert.Equal("[][" + Base16.Encode(expected) + "]", actual.ToString());
            Assert.Equal(expected.Length, actual.CopyTo(array));
            Assert.Equal(expected, array);
        }

        #endregion

        #region Ctor #2

        [Theory]
        [MemberData(nameof(Sizes))]
        public static void CtorWithCounterSize(int size)
        {
            var expected = new byte[size];
            var actual = new Nonce(size);
            var array = new byte[expected.Length];

            Assert.Equal(expected.Length, actual.Size);
            Assert.Equal(0, actual.FixedFieldSize);
            Assert.Equal(expected.Length, actual.CounterFieldSize);
            Assert.Equal(expected, actual.ToArray());
            Assert.Equal("[][" + Base16.Encode(expected) + "]", actual.ToString());
            Assert.Equal(expected.Length, actual.CopyTo(array));
            Assert.Equal(expected, array);
        }

        [Fact]
        public static void CtorWithNegativeCounterSize()
        {
            Assert.Throws<ArgumentOutOfRangeException>("counterFieldSize", () => new Nonce(-1));
        }

        [Fact]
        public static void CtorWithCounterSizeGreater15()
        {
            Assert.Throws<ArgumentOutOfRangeException>("counterFieldSize", () => new Nonce(16));
        }

        #endregion

        #region Ctor #3

        [Theory]
        [MemberData(nameof(Sizes))]
        public static void CtorWithFixedAndCounterSize(int size)
        {
            var @fixed = Utilities.RandomBytes.Slice(0, size / 2);
            var counter = new byte[size - @fixed.Length];

            var expected = new byte[size];
            @fixed.CopyTo(expected);
            var actual = new Nonce(@fixed, counter.Length);
            var array = new byte[expected.Length];

            Assert.Equal(expected.Length, actual.Size);
            Assert.Equal(@fixed.Length, actual.FixedFieldSize);
            Assert.Equal(counter.Length, actual.CounterFieldSize);
            Assert.Equal(expected, actual.ToArray());
            Assert.Equal("[" + Base16.Encode(@fixed) + "][" + Base16.Encode(counter) + "]", actual.ToString());
            Assert.Equal(expected.Length, actual.CopyTo(array));
            Assert.Equal(expected, array);
        }

        [Fact]
        public static void CtorWithFixedLargerThan15AndCounterSize()
        {
            Assert.Throws<ArgumentException>("fixedField", () => new Nonce(Utilities.RandomBytes.Slice(0, 16), -1));
        }

        [Fact]
        public static void CtorWithFixedAndNegativeCounterSize()
        {
            Assert.Throws<ArgumentOutOfRangeException>("counterFieldSize", () => new Nonce(Utilities.RandomBytes.Slice(0, 4), -1));
        }

        [Fact]
        public static void CtorWithFixedAndCounterSizeGreater15()
        {
            Assert.Throws<ArgumentOutOfRangeException>("counterFieldSize", () => new Nonce(Utilities.RandomBytes.Slice(0, 4), 12));
        }

        #endregion

        #region Ctor #4

        [Theory]
        [MemberData(nameof(Sizes))]
        public static void CtorWithFixedAndCounter(int size)
        {
            var @fixed = Utilities.RandomBytes.Slice(0, size / 2);
            var counter = Utilities.RandomBytes.Slice(size / 2, size - @fixed.Length);

            var expected = new byte[size];
            @fixed.CopyTo(expected);
            counter.CopyTo(expected.AsSpan().Slice(@fixed.Length));
            var actual = new Nonce(@fixed, counter);
            var array = new byte[expected.Length];

            Assert.Equal(expected.Length, actual.Size);
            Assert.Equal(@fixed.Length, actual.FixedFieldSize);
            Assert.Equal(counter.Length, actual.CounterFieldSize);
            Assert.Equal(expected, actual.ToArray());
            Assert.Equal("[" + Base16.Encode(@fixed) + "][" + Base16.Encode(counter) + "]", actual.ToString());
            Assert.Equal(expected.Length, actual.CopyTo(array));
            Assert.Equal(expected, array);
        }

        [Fact]
        public static void CtorWithFixedLargerThan15AndCounter()
        {
            Assert.Throws<ArgumentException>("fixedField", () => new Nonce(Utilities.RandomBytes.Slice(0, 16), Utilities.RandomBytes.Slice(0, 0)));
        }

        [Fact]
        public static void CtorWithFixedAndCounterLargerThan15()
        {
            Assert.Throws<ArgumentException>("counterField", () => new Nonce(Utilities.RandomBytes.Slice(0, 4), Utilities.RandomBytes.Slice(0, 12)));
        }

        #endregion

        #region Equals

        [Theory]
        [MemberData(nameof(Sizes))]
        public static void Equal(int size)
        {
            var expected = new Nonce(Utilities.RandomBytes.Slice(0, size), 0);
            var actual = new Nonce(Utilities.RandomBytes.Slice(0, size), 0);

            Assert.Equal(expected, actual);
            Assert.Equal(expected.GetHashCode(), actual.GetHashCode());
            Assert.True(actual.Equals(expected));
            Assert.True(actual.Equals((object)expected));
            Assert.True(actual == expected);
            Assert.False(actual != expected);
        }

        [Theory]
        [InlineData(new byte[] { })]
        [InlineData(new byte[] { 0xFF })]
        [InlineData(new byte[] { 0xFF, 0x00 })]
        [InlineData(new byte[] { 0x00, 0xFF })]
        [InlineData(new byte[] { 0xFF, 0xFF, 0x01 })]
        public static void NotEqual(byte[] bytes)
        {
            var expected = new Nonce(new byte[] { 0xFF, 0xFF }, 0);
            var actual = new Nonce(bytes, 0);

            Assert.NotEqual(expected, actual);
            Assert.NotEqual(expected.GetHashCode(), actual.GetHashCode());
            Assert.False(expected.Equals(actual));
            Assert.False(expected.Equals((object)actual));
            Assert.False(expected == actual);
            Assert.True(expected != actual);
        }

        #endregion

        #region CompareTo

        [Theory]
        [MemberData(nameof(Sizes))]
        public static void CompareSize(int second)
        {
            const int first = 5;
            var expected = Math.Sign(first.CompareTo(second));
            var left = new Nonce(first);
            var right = new Nonce(second);
            var actual = left.CompareTo(right);

            Assert.Equal(expected, actual);
            Assert.Equal(expected < 0, left < right);
            Assert.Equal(expected <= 0, left <= right);
            Assert.Equal(expected > 0, left > right);
            Assert.Equal(expected >= 0, left >= right);
        }

        [Theory]
        [InlineData(3, 1)]
        [InlineData(3, 2)]
        [InlineData(3, 3)]
        [InlineData(3, 4)]
        [InlineData(3, 5)]
        [InlineData(0x1000, 0)]
        [InlineData(0x1000, 0x10)]
        [InlineData(0x1000, 0x1000)]
        [InlineData(0x1000, 0x100000)]
        [InlineData(0x1000, 0x10000000)]
        public static void CompareValue(int first, int second)
        {
            var expected = Math.Sign(first.CompareTo(second));
            var left = new Nonce(4) + first;
            var right = new Nonce(4) + second;
            var actual = left.CompareTo(right);

            Assert.Equal(expected, actual);
            Assert.Equal(expected < 0, left < right);
            Assert.Equal(expected <= 0, left <= right);
            Assert.Equal(expected > 0, left > right);
            Assert.Equal(expected >= 0, left >= right);
        }

        #endregion

        #region Operator +

        [Theory]
        [InlineData(new byte[] { 0xFE, 0xED, 0xDC, 0xCB, 0x12, 0x34, 0x56, 0x78 }, new byte[] { 0x00, 0x00, 0x00, 0x00 }, 0x12345678)]
        [InlineData(new byte[] { 0xFE, 0xED, 0xDC, 0xCB, 0x12, 0x34, 0x56, 0x78 }, new byte[] { 0x10, 0x30, 0x50, 0x70 }, 0x02040608)]
        public static void AddNoCarry(byte[] expected, byte[] left, int right)
        {
            var actual = new Nonce(new byte[] { 0xFE, 0xED, 0xDC, 0xCB }, left) + right;

            Assert.Equal(expected, actual.ToArray());
        }

        [Theory]
        [InlineData(new byte[] { 0xFE, 0xED, 0xDC, 0xCB, 0x01, 0xFE, 0x01, 0x00 }, new byte[] { 0x00, 0xFF, 0x00, 0xFF }, 0x00FF0001)]
        [InlineData(new byte[] { 0xFE, 0xED, 0xDC, 0xCB, 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0xFF, 0xFF, 0xFF }, 0x00000001)]
        [InlineData(new byte[] { 0xFE, 0xED, 0xDC, 0xCB, 0xFE, 0xE1, 0x6E, 0x45 }, new byte[] { 0xA3, 0x33, 0x78, 0x51 }, 0x5BADF5F4)]
        public static void AddCarry(byte[] expected, byte[] left, int right)
        {
            var actual = new Nonce(new byte[] { 0xFE, 0xED, 0xDC, 0xCB }, left) + right;

            Assert.Equal(expected, actual.ToArray());
        }

        [Theory]
        [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, 1)]
        [InlineData(new byte[] { 0xFF, 0xF0, 0xBD, 0xBF }, 1000001)]
        public static void AddOverflow(byte[] left, int right)
        {
            Assert.Throws<OverflowException>(() => new Nonce(new byte[] { 0xFE, 0xED, 0xDC, 0xCB }, left) + right);
        }

        [Fact]
        public static void AddNegative()
        {
            Assert.Throws<ArgumentOutOfRangeException>("addend", () => new Nonce() + (-1));
        }

        #endregion

        #region Operator ++

        [Fact]
        public static void IncrementNoCarry()
        {
            var expected = new byte[] { 0xFE, 0xED, 0xDC, 0xCB, 0xFF, 0xFF, 0xFF, 0xFF };
            var actual = new Nonce(new byte[] { 0xFE, 0xED, 0xDC, 0xCB }, new byte[] { 0xFF, 0xFF, 0xFF, 0xFE });

            actual++;

            Assert.Equal(expected, actual.ToArray());
        }

        [Fact]
        public static void IncrementCarry()
        {
            var expected = new byte[] { 0xFE, 0xED, 0xDC, 0xCB, 0x01, 0x00, 0x00, 0x00 };
            var actual = new Nonce(new byte[] { 0xFE, 0xED, 0xDC, 0xCB }, new byte[] { 0x00, 0xFF, 0xFF, 0xFF });

            actual++;

            Assert.Equal(expected, actual.ToArray());
        }

        [Fact]
        public static void IncrementOverflow()
        {
            var actual = new Nonce(new byte[] { 0xFE, 0xED, 0xDC, 0xCB }, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF });

            Assert.Throws<OverflowException>(() => ++actual);
        }

        #endregion

        #region Operator ^

        [Fact]
        public static void Xor()
        {
            var bytes1 = Utilities.RandomBytes.Slice(0, 12);
            var bytes2 = Utilities.RandomBytes.Slice(12, bytes1.Length);
            var expected = new byte[bytes1.Length];
            var actual = new Nonce(ReadOnlySpan<byte>.Empty, bytes1) ^ bytes2;

            for (var i = 0; i < expected.Length; i++)
            {
                expected[i] = (byte)(bytes1[i] ^ bytes2[i]);
            }

            Assert.Equal(expected, actual.ToArray());
            Assert.Equal(expected.Length, actual.Size);
            Assert.Equal(expected.Length, actual.FixedFieldSize);
            Assert.Equal(0, actual.CounterFieldSize);
        }

        [Fact]
        public static void XorWrongLength()
        {
            Assert.Throws<ArgumentException>("bytes", () => new Nonce(12) ^ new byte[11]);
        }

        #endregion

        #region Layout

        [Fact]
        public static void Layout()
        {
            var expected = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            var @fixed = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            var counter = 0x05060708;
            var actual = new Nonce(@fixed, 4) + counter;

            Assert.Equal(expected, actual.ToArray());
        }

        #endregion
    }
}
