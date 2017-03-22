using System;
using NSec.Cryptography.Formatting;
using Xunit;

namespace NSec.Tests.Formatting
{
    public static class Asn1WriterTests
    {
        [Theory]
        [InlineData(false, new byte[] { 0x01, 0x01, 0x00 })]
        [InlineData(true, new byte[] { 0x01, 0x01, 0xFF })]
        public static void Bool(bool value, byte[] expected)
        {
            var writer = new Asn1Writer(new byte[expected.Length]);
            writer.Bool(value);
            Assert.Equal(expected, writer.Bytes.ToArray());
        }

        [Theory]
        [InlineData(new byte[] { }, new byte[] { 0x03, 0x01, 0x00 })]
        [InlineData(new byte[] { 0x01 }, new byte[] { 0x03, 0x02, 0x00, 0x01 })]
        [InlineData(new byte[] { 0x01, 0x23 }, new byte[] { 0x03, 0x03, 0x00, 0x01, 0x23 })]
        [InlineData(new byte[] { 0x01, 0x23, 0x45 }, new byte[] { 0x03, 0x04, 0x00, 0x01, 0x23, 0x45 })]
        [InlineData(new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }, new byte[] { 0x03, 0x09, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef })]
        public static void BitString(byte[] value, byte[] expected)
        {
            var writer = new Asn1Writer(new byte[expected.Length]);
            writer.BitString(value);
            Assert.Equal(expected, writer.Bytes.ToArray());
        }

        [Theory]
        [InlineData(0, new byte[] { 0x02, 0x01, 0x00 })]
        [InlineData(127, new byte[] { 0x02, 0x01, 0x7F })]
        [InlineData(128, new byte[] { 0x02, 0x02, 0x00, 0x80 })]
        [InlineData(256, new byte[] { 0x02, 0x02, 0x01, 0x00 })]
        [InlineData(32767, new byte[] { 0x02, 0x02, 0x7F, 0xFF })]
        [InlineData(32768, new byte[] { 0x02, 0x03, 0x00, 0x80, 0x00 })]
        [InlineData(-128, new byte[] { 0x02, 0x01, 0x80 })]
        [InlineData(-129, new byte[] { 0x02, 0x02, 0xFF, 0x7F })]
        [InlineData(-32768, new byte[] { 0x02, 0x02, 0x80, 0x00 })]
        public static void Integer32(int value, byte[] expected)
        {
            var writer = new Asn1Writer(new byte[expected.Length]);
            writer.Integer(value);
            Assert.Equal(expected, writer.Bytes.ToArray());
        }

        [Theory]
        [InlineData(0L, new byte[] { 0x02, 0x01, 0x00 })]
        [InlineData(127L, new byte[] { 0x02, 0x01, 0x7F })]
        [InlineData(128L, new byte[] { 0x02, 0x02, 0x00, 0x80 })]
        [InlineData(256L, new byte[] { 0x02, 0x02, 0x01, 0x00 })]
        [InlineData(32767L, new byte[] { 0x02, 0x02, 0x7F, 0xFF })]
        [InlineData(32768L, new byte[] { 0x02, 0x03, 0x00, 0x80, 0x00 })]
        [InlineData(-128L, new byte[] { 0x02, 0x01, 0x80 })]
        [InlineData(-129L, new byte[] { 0x02, 0x02, 0xFF, 0x7F })]
        [InlineData(-32768L, new byte[] { 0x02, 0x02, 0x80, 0x00 })]
        [InlineData(int.MinValue, new byte[] { 0x02, 0x04, 0x80, 0x00, 0x00, 0x00 })]
        [InlineData(long.MinValue, new byte[] { 0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
        public static void Integer64(long value, byte[] expected)
        {
            var writer = new Asn1Writer(new byte[expected.Length]);
            writer.Integer(value);
            Assert.Equal(expected, writer.Bytes.ToArray());
        }

        [Fact]
        public static void Null()
        {
            var expected = new byte[] { 0x05, 0x00 };
            var writer = new Asn1Writer(new byte[expected.Length]);
            writer.Null();
            Assert.Equal(expected, writer.Bytes.ToArray());
        }

        [Theory]
        [InlineData(new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d }, new byte[] { 0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d })]
        public static void ObjectIdentifier(byte[] value, byte[] expected)
        {
            var writer = new Asn1Writer(new byte[expected.Length]);
            writer.ObjectIdentifier(value);
            Assert.Equal(expected, writer.Bytes.ToArray());
        }

        [Theory]
        [InlineData(new byte[] { }, new byte[] { 0x04, 0x00 })]
        [InlineData(new byte[] { 0x01 }, new byte[] { 0x04, 0x01, 0x01 })]
        [InlineData(new byte[] { 0x01, 0x23 }, new byte[] { 0x04, 0x02, 0x01, 0x23 })]
        [InlineData(new byte[] { 0x01, 0x23, 0x45 }, new byte[] { 0x04, 0x03, 0x01, 0x23, 0x45 })]
        [InlineData(new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }, new byte[] { 0x04, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef })]
        public static void OctetString(byte[] value, byte[] expected)
        {
            var writer = new Asn1Writer(new byte[expected.Length]);
            writer.OctetString(value);
            Assert.Equal(expected, writer.Bytes.ToArray());
        }

        [Fact]
        public static void SequenceStackOverflow()
        {
            var writer = new Asn1Writer(new byte[2], 3);
            writer.End();
            writer.End();
            writer.End();
            try { writer.End(); Assert.True(false); } catch (IndexOutOfRangeException) { } // cannot use Assert.Throws
        }

        [Fact]
        public static void SequenceStackUnderflow()
        {
            var writer = new Asn1Writer(new byte[0]);
            try { writer.BeginSequence(); Assert.True(false); } catch (IndexOutOfRangeException) { } // cannot use Assert.Throws
        }

        [Theory]
        [InlineData(1, new byte[] { 0x30, 0x00 })]
        [InlineData(2, new byte[] { 0x30, 0x02, 0x30, 0x00 })]
        [InlineData(3, new byte[] { 0x30, 0x04, 0x30, 0x02, 0x30, 0x00 })]
        [InlineData(4, new byte[] { 0x30, 0x06, 0x30, 0x04, 0x30, 0x02, 0x30, 0x00 })]
        public static void Sequence(int depth, byte[] expected)
        {
            var writer = new Asn1Writer(new byte[expected.Length], depth);
            for (var i = 0; i < depth; i++)
                writer.End();
            for (var i = 0; i < depth; i++)
                writer.BeginSequence();
            Assert.Equal(expected, writer.Bytes.ToArray());
        }

        [Theory]
        [InlineData(new int[] { }, new byte[] { 0x30, 0x00 })]
        [InlineData(new int[] { 1 }, new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 })]
        [InlineData(new int[] { 1, 2 }, new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 })]
        [InlineData(new int[] { 1, 2, 3 }, new byte[] { 0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03 })]
        public static void IntegerSequence(int[] values, byte[] expected)
        {
            var writer = new Asn1Writer(new byte[expected.Length], 1);
            writer.End();
            for (var i = 0; i < values.Length; i++)
                writer.Integer(values[values.Length - i - 1]);
            writer.BeginSequence();
            Assert.Equal(expected, writer.Bytes.ToArray());
        }
    }
}
