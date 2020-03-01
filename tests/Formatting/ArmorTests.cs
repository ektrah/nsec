using System;
using System.Text;
using NSec.Cryptography.Formatting;
using Xunit;

namespace NSec.Tests.Formatting
{
    public static class ArmorTests
    {
        private const string s_beginLabel = "-----BEGIN-----";
        private const string s_endLabel = "-----END-----";

        private static readonly byte[] s_utf8BeginLabel = Encoding.UTF8.GetBytes(s_beginLabel);
        private static readonly byte[] s_utf8EndLabel = Encoding.UTF8.GetBytes(s_endLabel);

        [Theory]
        [InlineData("", "")]
        [InlineData("f", "Zg==")]
        [InlineData("fo", "Zm8=")]
        [InlineData("foo", "Zm9v")]
        [InlineData("foob", "Zm9vYg==")]
        [InlineData("fooba", "Zm9vYmE=")]
        [InlineData("foobar", "Zm9vYmFy")]
        [InlineData("a", "YQ==")]
        public static void Encode(string chars, string base64)
        {
            var bytes = Encoding.UTF8.GetBytes(chars);
            var utf8 = new byte[Armor.GetEncodedToUtf8Length(bytes.Length, s_utf8BeginLabel, s_utf8EndLabel)];
            Armor.EncodeToUtf8(bytes, s_utf8BeginLabel, s_utf8EndLabel, utf8);
            var actual = Encoding.UTF8.GetString(utf8);
            var expected = (s_beginLabel + "\r\n") + (string.IsNullOrEmpty(base64) ? string.Empty : base64 + "\r\n") + (s_endLabel + "\r\n");
            Assert.Equal(expected, actual);
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
        public static void Decode(string base64, string chars)
        {
            var utf8 = Encoding.UTF8.GetBytes(s_beginLabel + base64 + s_endLabel);
            var bytes = new byte[Encoding.UTF8.GetByteCount(chars)];
            var success = Armor.TryDecodeFromUtf8(utf8, s_utf8BeginLabel, s_utf8EndLabel, bytes, out var written);
            Assert.True(success);
            Assert.Equal(bytes.Length, written);
            var actual = Encoding.UTF8.GetString(bytes);
            var expected = chars;
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData("Z")]
        [InlineData("Zg")]
        [InlineData("Zg=")]
        [InlineData("Zm9vY")]
        [InlineData("Zm9vYg")]
        [InlineData("Zm9vYg=")]
        public static void DecodeInvalidLength(string base64)
        {
            var utf8 = Encoding.UTF8.GetBytes(s_beginLabel + base64 + s_endLabel);
            var success = Armor.TryDecodeFromUtf8(utf8, s_utf8BeginLabel, s_utf8EndLabel, new byte[20], out var written);
            Assert.False(success);
            Assert.Equal(0, written);
        }

        [Theory]
        [InlineData("====")]
        [InlineData("Z===")]
        [InlineData("Zg=A")]
        public static void DecodeInvalidPadding(string base64)
        {
            var utf8 = Encoding.UTF8.GetBytes(s_beginLabel + base64 + s_endLabel);
            var success = Armor.TryDecodeFromUtf8(utf8, s_utf8BeginLabel, s_utf8EndLabel, new byte[20], out var written);
            Assert.False(success);
            Assert.Equal(0, written);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        public static void DecodeInvalidChars(int pos)
        {
            for (var i = 0; i < 65536; i++)
            {
                var expected = (i >= 'A' && i <= 'Z' ||
                                i >= 'a' && i <= 'z' ||
                                i >= '0' && i <= '9' ||
                                i == '+' || i == '/' ||
                                pos == 3 && i == '=');

                var base64 = "AAA".Insert(pos, new string((char)i, 1));
                var utf8 = Encoding.UTF8.GetBytes(s_beginLabel + base64 + s_endLabel);
                var actual = Armor.TryDecodeFromUtf8(utf8, s_utf8BeginLabel, s_utf8EndLabel, new byte[20], out _);
                Assert.Equal(expected, actual);
            }
        }
    }
}
