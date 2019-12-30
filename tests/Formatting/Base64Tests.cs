using System;
using System.Text;
using NSec.Experimental.Text;
using Xunit;

namespace NSec.Tests.Formatting
{
    public static class Base64Tests
    {
        [Theory]
        [InlineData("", "")]
        [InlineData("f", "Zg==")]
        [InlineData("fo", "Zm8=")]
        [InlineData("foo", "Zm9v")]
        [InlineData("foob", "Zm9vYg==")]
        [InlineData("fooba", "Zm9vYmE=")]
        [InlineData("foobar", "Zm9vYmFy")]
        [InlineData("a", "YQ==")]
        public static void Encode(string input, string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            var base64 = new char[Base64.GetEncodedLength(bytes.Length)];
            Base64.Encode(bytes, base64);
            Assert.Equal(expected, new string(base64));
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "Zg==")]
        [InlineData("fo", "Zm8=")]
        [InlineData("foo", "Zm9v")]
        [InlineData("foob", "Zm9vYg==")]
        [InlineData("fooba", "Zm9vYmE=")]
        [InlineData("foobar", "Zm9vYmFy")]
        [InlineData("a", "YQ==")]
        public static void EncodeString(string input, string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            Assert.Equal(expected, Base64.Encode(bytes));
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("Zg==", "f")]
        [InlineData("Zm8=", "fo")]
        [InlineData("Zm9v", "foo")]
        [InlineData("Zm9vYg==", "foob")]
        [InlineData("Zm9vYmE=", "fooba")]
        [InlineData("Zm9vYmFy", "foobar")]
        [InlineData("YQ==", "a")]
        [InlineData("YR==", "a")]
        public static void Decode(string input, string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(expected);
            var base64 = input.ToCharArray();
            Assert.True(Base64.TryGetDecodedLength(base64, out var length));
            var actual = new byte[length];
            Assert.True(Base64.TryDecode(base64, actual));
            Assert.Equal(bytes, actual);
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("Zg==", "f")]
        [InlineData("Zm8=", "fo")]
        [InlineData("Zm9v", "foo")]
        [InlineData("Zm9vYg==", "foob")]
        [InlineData("Zm9vYmE=", "fooba")]
        [InlineData("Zm9vYmFy", "foobar")]
        public static void DecodeString(string input, string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(expected);
            Assert.Equal(bytes, Base64.Decode(input));
        }

        [Theory]
        [InlineData("Z")]
        [InlineData("Zg")]
        [InlineData("Zg=")]
        [InlineData("Zm9vY")]
        [InlineData("Zm9vYg")]
        [InlineData("Zm9vYg=")]
        public static void DecodeInvalidLength(string input)
        {
            var base64 = input.ToCharArray();
            Assert.False(Base64.TryGetDecodedLength(base64, out var length));
            Assert.Equal(0, length);
        }

        [Theory]
        [InlineData("====")]
        [InlineData("Z===")]
        [InlineData("Zg=A")]
        public static void DecodeInvalidPadding(string input)
        {
            var base64 = input.ToCharArray();
            Assert.True(Base64.TryGetDecodedLength(base64, out var length));
            var actual = new byte[length];
            Assert.False(Base64.TryDecode(base64, actual));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        public static void DecodeInvalidChars(int pos)
        {
            var base64 = "AAAA".ToCharArray();
            for (var i = 0; i < 65536; i++)
            {
                if (i >= 'A' && i <= 'Z' ||
                    i >= 'a' && i <= 'z' ||
                    i >= '0' && i <= '9' ||
                    i == '+' || i == '/' ||
                    pos == 3 && i == '=')
                    continue;
                base64[pos] = (char)i;
                Assert.True(Base64.TryGetDecodedLength(base64, out var length));
                var actual = new byte[length];
                Assert.False(Base64.TryDecode(base64, actual));
            }
        }

        [Fact]
        public static void DecodeNull()
        {
            Assert.Throws<ArgumentNullException>("base64", () => Base64.Decode((string)null!));
        }

        [Fact]
        public static void TryDecodeNull()
        {
            Assert.Throws<ArgumentNullException>("base64", () => Base64.TryDecode((string)null!, Span<byte>.Empty));
        }

        [Fact]
        public static void TryGetDecodedLengthNull()
        {
            Assert.Throws<ArgumentNullException>("base64", () => Base64.TryGetDecodedLength((string)null!, out var decodedLength));
        }
    }
}
