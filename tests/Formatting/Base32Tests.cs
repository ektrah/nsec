using System;
using System.Text;
using NSec.Experimental.Text;
using Xunit;

namespace NSec.Tests.Formatting
{
    public static class Base32Tests
    {
        [Theory]
        [InlineData("", "")]
        [InlineData("f", "MY======")]
        [InlineData("fo", "MZXQ====")]
        [InlineData("foo", "MZXW6===")]
        [InlineData("foob", "MZXW6YQ=")]
        [InlineData("fooba", "MZXW6YTB")]
        [InlineData("foobar", "MZXW6YTBOI======")]
        public static void Encode(string input, string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            var base32 = new char[Base32.GetEncodedLength(bytes.Length)];
            Base32.Encode(bytes, base32);
            Assert.Equal(expected, new string(base32));
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "MY======")]
        [InlineData("fo", "MZXQ====")]
        [InlineData("foo", "MZXW6===")]
        [InlineData("foob", "MZXW6YQ=")]
        [InlineData("fooba", "MZXW6YTB")]
        [InlineData("foobar", "MZXW6YTBOI======")]
        public static void EncodeString(string input, string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            Assert.Equal(expected, Base32.Encode(bytes));
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("MY======", "f")]
        [InlineData("MZXQ====", "fo")]
        [InlineData("MZXW6===", "foo")]
        [InlineData("MZXW6YQ=", "foob")]
        [InlineData("MZXW6YTB", "fooba")]
        [InlineData("MZXW6YTBOI======", "foobar")]
        [InlineData("my======", "f")]
        [InlineData("mzxq====", "fo")]
        [InlineData("mzxw6===", "foo")]
        [InlineData("mzxw6yq=", "foob")]
        [InlineData("mzxw6ytb", "fooba")]
        [InlineData("mzxw6ytboi======", "foobar")]
        public static void Decode(string input, string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(expected);
            var base32 = input.ToCharArray();
            Assert.True(Base32.TryGetDecodedLength(base32, out var length));
            var actual = new byte[length];
            Assert.True(Base32.TryDecode(base32, actual));
            Assert.Equal(bytes, actual);
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("MY======", "f")]
        [InlineData("MZXQ====", "fo")]
        [InlineData("MZXW6===", "foo")]
        [InlineData("MZXW6YQ=", "foob")]
        [InlineData("MZXW6YTB", "fooba")]
        [InlineData("MZXW6YTBOI======", "foobar")]
        public static void DecodeString(string input, string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(expected);
            Assert.Equal(bytes, Base32.Decode(input));
        }

        [Theory]
        [InlineData("M")]
        [InlineData("MZ")]
        [InlineData("MZX")]
        [InlineData("MZXW")]
        [InlineData("MZXW6")]
        [InlineData("MZXW6Y")]
        [InlineData("MZXW6YT")]
        [InlineData("MZXW6YTBO")]
        [InlineData("MZXW6YTBOI")]
        public static void DecodeInvalidLength(string input)
        {
            var base32 = input.ToCharArray();
            Assert.False(Base32.TryGetDecodedLength(base32, out var length));
            Assert.Equal(0, length);
        }

        [Theory]
        [InlineData("========")]
        [InlineData("M=======")]
        [InlineData("MY=====A")]
        [InlineData("MZX=====")]
        [InlineData("MZXQ===A")]
        [InlineData("MZXW6==A")]
        [InlineData("MZXW6Y==")]
        public static void DecodeInvalidPadding(string input)
        {
            var base32 = input.ToCharArray();
            Assert.True(Base32.TryGetDecodedLength(base32, out var length));
            var actual = new byte[length];
            Assert.False(Base32.TryDecode(base32, actual));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(6)]
        [InlineData(7)]
        public static void DecodeInvalidChars(int pos)
        {
            var base32 = "AAAAAAAA".ToCharArray();
            for (var i = 0; i < 65536; i++)
            {
                if (i >= 'A' && i <= 'Z' ||
                    i >= 'a' && i <= 'z' ||
                    i >= '2' && i <= '7' ||
                    pos == 7 && i == '=')
                    continue;
                base32[pos] = (char)i;
                Assert.True(Base32.TryGetDecodedLength(base32, out var length));
                var actual = new byte[length];
                Assert.False(Base32.TryDecode(base32, actual));
            }
        }

        [Fact]
        public static void DecodeNull()
        {
            Assert.Throws<ArgumentNullException>("base32", () => Base32.Decode((string)null!));
        }

        [Fact]
        public static void TryDecodeNull()
        {
            Assert.Throws<ArgumentNullException>("base32", () => Base32.TryDecode((string)null!, Span<byte>.Empty));
        }

        [Fact]
        public static void TryGetDecodedLengthNull()
        {
            Assert.Throws<ArgumentNullException>("base32", () => Base32.TryGetDecodedLength((string)null!, out var decodedLength));
        }
    }
}
