using System;
using System.Text;
using NSec.Experimental.Text;
using Xunit;

namespace NSec.Tests.Formatting
{
    public static class Base16Tests
    {
        [Theory]
        [InlineData("", "")]
        [InlineData("f", "66")]
        [InlineData("fo", "666F")]
        [InlineData("foo", "666F6F")]
        [InlineData("foob", "666F6F62")]
        [InlineData("fooba", "666F6F6261")]
        [InlineData("foobar", "666F6F626172")]
        public static void Encode(string input, string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            var base16 = new char[Base16.GetEncodedLength(bytes.Length)];
            Base16.Encode(bytes, base16);
            Assert.Equal(expected, new string(base16));
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "66")]
        [InlineData("fo", "666F")]
        [InlineData("foo", "666F6F")]
        [InlineData("foob", "666F6F62")]
        [InlineData("fooba", "666F6F6261")]
        [InlineData("foobar", "666F6F626172")]
        public static void EncodeString(string input, string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            Assert.Equal(expected, Base16.Encode(bytes));
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("66", "f")]
        [InlineData("666F", "fo")]
        [InlineData("666F6F", "foo")]
        [InlineData("666F6F62", "foob")]
        [InlineData("666F6F6261", "fooba")]
        [InlineData("666F6F626172", "foobar")]
        [InlineData("666f", "fo")]
        [InlineData("666f6f", "foo")]
        [InlineData("666f6f62", "foob")]
        [InlineData("666f6f6261", "fooba")]
        [InlineData("666f6f626172", "foobar")]
        public static void Decode(string input, string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(expected);
            var base16 = input.ToCharArray();
            Assert.True(Base16.TryGetDecodedLength(base16, out var length));
            var actual = new byte[length];
            Assert.True(Base16.TryDecode(base16, actual));
            Assert.Equal(bytes, actual);
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("66", "f")]
        [InlineData("666F", "fo")]
        [InlineData("666F6F", "foo")]
        [InlineData("666F6F62", "foob")]
        [InlineData("666F6F6261", "fooba")]
        [InlineData("666F6F626172", "foobar")]
        public static void DecodeString(string input, string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(expected);
            Assert.Equal(bytes, Base16.Decode(input));
        }

        [Theory]
        [InlineData("6")]
        [InlineData("666")]
        [InlineData("666F6")]
        [InlineData("666F6F6")]
        public static void DecodeInvalidLength(string input)
        {
            var base16 = input.ToCharArray();
            Assert.False(Base16.TryGetDecodedLength(base16, out var length));
            Assert.Equal(0, length);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        public static void DecodeInvalidChars(int pos)
        {
            var base16 = "00".ToCharArray();
            for (var i = 0; i < 65536; i++)
            {
                if (i >= '0' && i <= '9' ||
                    i >= 'A' && i <= 'F' ||
                    i >= 'a' && i <= 'f')
                    continue;
                base16[pos] = (char)i;
                Assert.True(Base16.TryGetDecodedLength(base16, out var length));
                var actual = new byte[length];
                Assert.False(Base16.TryDecode(base16, actual));
            }
        }

        [Fact]
        public static void DecodeNull()
        {
            Assert.Throws<ArgumentNullException>("base16", () => Base16.Decode((string)null!));
        }

        [Fact]
        public static void TryDecodeNull()
        {
            Assert.Throws<ArgumentNullException>("base16", () => Base16.TryDecode((string)null!, Span<byte>.Empty));
        }

        [Fact]
        public static void TryGetDecodedLengthNull()
        {
            Assert.Throws<ArgumentNullException>("base16", () => Base16.TryGetDecodedLength((string)null!, out var decodedLength));
        }
    }
}
