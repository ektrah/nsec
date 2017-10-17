using System;
using NSec.Cryptography.Formatting;
using Xunit;

namespace NSec.Tests.Formatting
{
    public static class Asn1ReaderTests
    {
        [Theory]
        [InlineData(new byte[] { 0x01, 0x01, 0x00 }, false)]
        [InlineData(new byte[] { 0x01, 0x01, 0xFF }, true)]
        public static void Bool(byte[] value, bool expected)
        {
            var reader = new Asn1Reader(value);
            Assert.Equal(expected, reader.Bool());
            Assert.True(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x01, 0x00 })]
        [InlineData(new byte[] { 0x01, 0x01, 0x01 })]
        [InlineData(new byte[] { 0x01, 0x01, 0x80 })]
        [InlineData(new byte[] { 0x01, 0x01, 0xFE })]
        [InlineData(new byte[] { 0x01, 0x02, 0x00, 0x00 })]
        [InlineData(new byte[] { 0x01, 0x02, 0xFF, 0xFF })]
        public static void BoolInvalid(byte[] value)
        {
            var reader = new Asn1Reader(value);
            Assert.False(reader.Bool());
            Assert.False(reader.Success);
            Assert.False(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x03, 0x01, 0x00 }, new byte[] { })]
        [InlineData(new byte[] { 0x03, 0x02, 0x00, 0x01 }, new byte[] { 0x01 })]
        [InlineData(new byte[] { 0x03, 0x09, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }, new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef })]
        public static void BitString(byte[] value, byte[] expected)
        {
            var reader = new Asn1Reader(value);
            Assert.Equal(expected, reader.BitString().ToArray());
            Assert.True(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x03, 0x00 })]
        [InlineData(new byte[] { 0x03, 0x01 })]
        [InlineData(new byte[] { 0x03, 0x01, 0x08 })]
        [InlineData(new byte[] { 0x03, 0x01, 0x80 })]
        [InlineData(new byte[] { 0x03, 0x01, 0xFF })]
        public static void BitStringInvalid(byte[] value)
        {
            var reader = new Asn1Reader(value);
            Assert.Equal(new byte[0], reader.BitString().ToArray());
            Assert.False(reader.Success);
            Assert.False(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x02, 0x01, 0x00 }, 0)]
        [InlineData(new byte[] { 0x02, 0x01, 0x7F }, 127)]
        [InlineData(new byte[] { 0x02, 0x02, 0x00, 0x80 }, 128)]
        [InlineData(new byte[] { 0x02, 0x02, 0x01, 0x00 }, 256)]
        [InlineData(new byte[] { 0x02, 0x02, 0x7F, 0xFF }, 32767)]
        [InlineData(new byte[] { 0x02, 0x03, 0x00, 0x80, 0x00 }, 32768)]
        [InlineData(new byte[] { 0x02, 0x01, 0xFF }, -1)]
        [InlineData(new byte[] { 0x02, 0x01, 0x80 }, -128)]
        [InlineData(new byte[] { 0x02, 0x02, 0xFF, 0x7F }, -129)]
        [InlineData(new byte[] { 0x02, 0x02, 0x80, 0x00 }, -32768)]
        [InlineData(new byte[] { 0x02, 0x04, 0x80, 0x00, 0x00, 0x00 }, int.MinValue)]
        public static void Integer32(byte[] value, int expected)
        {
            var reader = new Asn1Reader(value);
            Assert.Equal(expected, reader.Integer32());
            Assert.True(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x02, 0x00 })] //  contents octets shall consist of one or more octets
        [InlineData(new byte[] { 0x02, 0x02, 0x00, 0x7F })] // the bits of the first octet and bit 8 of the second octet shall not all be zero
        [InlineData(new byte[] { 0x02, 0x02, 0xFF, 0x80 })] // the bits of the first octet and bit 8 of the second octet shall not all be ones
        [InlineData(new byte[] { 0x02, 0x05, 0x01, 0x23, 0x45, 0x67, 0x89 })]
        public static void Integer32Invalid(byte[] value)
        {
            var reader = new Asn1Reader(value);
            Assert.Equal(0, reader.Integer32());
            Assert.False(reader.Success);
            Assert.False(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x02, 0x01, 0x00 }, 0L)]
        [InlineData(new byte[] { 0x02, 0x01, 0x7F }, 127L)]
        [InlineData(new byte[] { 0x02, 0x02, 0x00, 0x80 }, 128L)]
        [InlineData(new byte[] { 0x02, 0x02, 0x01, 0x00 }, 256L)]
        [InlineData(new byte[] { 0x02, 0x02, 0x7F, 0xFF }, 32767L)]
        [InlineData(new byte[] { 0x02, 0x03, 0x00, 0x80, 0x00 }, 32768L)]
        [InlineData(new byte[] { 0x02, 0x01, 0xFF }, -1L)]
        [InlineData(new byte[] { 0x02, 0x01, 0x80 }, -128L)]
        [InlineData(new byte[] { 0x02, 0x02, 0xFF, 0x7F }, -129L)]
        [InlineData(new byte[] { 0x02, 0x02, 0x80, 0x00 }, -32768L)]
        [InlineData(new byte[] { 0x02, 0x04, 0x80, 0x00, 0x00, 0x00 }, int.MinValue)]
        [InlineData(new byte[] { 0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, long.MinValue)]
        public static void Integer64(byte[] value, long expected)
        {
            var reader = new Asn1Reader(value);
            Assert.Equal(expected, reader.Integer64());
            Assert.True(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x02, 0x00 })] //  contents octets shall consist of one or more octets
        [InlineData(new byte[] { 0x02, 0x02, 0x00, 0x7F })] // the bits of the first octet and bit 8 of the second octet shall not all be zero
        [InlineData(new byte[] { 0x02, 0x02, 0xFF, 0x80 })] // the bits of the first octet and bit 8 of the second octet shall not all be ones
        [InlineData(new byte[] { 0x02, 0x09, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
        public static void Integer64Invalid(byte[] value)
        {
            var reader = new Asn1Reader(value);
            Assert.Equal(0, reader.Integer64());
            Assert.False(reader.Success);
            Assert.False(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x04 })]
        [InlineData(new byte[] { 0x04, 0x01 })]
        [InlineData(new byte[] { 0x04, 0x80 })]
        [InlineData(new byte[] { 0x04, 0x81, 0x00 })]
        [InlineData(new byte[] { 0x04, 0x81, 0x01, 0x17 })]
        [InlineData(new byte[] { 0x04, 0x82, 0x00, 0x01, 0x17 })]
        [InlineData(new byte[] { 0x04, 0x84, 0x80, 0x00, 0x00, 0x00 })]
        [InlineData(new byte[] { 0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF })]
        [InlineData(new byte[] { 0x04, 0xFF })]
        public static void LengthInvalid(byte[] value)
        {
            var reader = new Asn1Reader(value);
            Assert.Equal(new byte[0], reader.OctetString().ToArray());
            Assert.False(reader.Success);
            Assert.False(reader.SuccessComplete);
        }

        [Fact]
        public static void Null()
        {
            var value = new byte[] { 0x05, 0x00 };
            var reader = new Asn1Reader(value);
            reader.Null();
            Assert.True(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x05, 0x01, 0xFF })]
        [InlineData(new byte[] { 0x05, 0x80 })]
        [InlineData(new byte[] { 0x05, 0x81, 0x00 })]
        [InlineData(new byte[] { 0x05, 0x81, 0x01, 0xFF })]
        public static void NullInvalid(byte[] value)
        {
            var reader = new Asn1Reader(value);
            reader.Null();
            Assert.False(reader.Success);
            Assert.False(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d }, new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d })]
        public static void ObjectIdentifier(byte[] value, byte[] expected)
        {
            var reader = new Asn1Reader(value);
            Assert.Equal(expected, reader.ObjectIdentifier().ToArray());
            Assert.True(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x04, 0x00 }, new byte[] { })]
        [InlineData(new byte[] { 0x04, 0x01, 0x01 }, new byte[] { 0x01 })]
        [InlineData(new byte[] { 0x04, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }, new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef })]
        public static void OctetString(byte[] value, byte[] expected)
        {
            var reader = new Asn1Reader(value);
            Assert.Equal(expected, reader.OctetString().ToArray());
            Assert.True(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x24, 0x80, 0x04, 0x02, 0x0A, 0x3B, 0x04, 0x04, 0x5F, 0x29, 0x1C, 0xD0, 0x00, 0x00 })] // The constructed form of encoding shall not be used
        [InlineData(new byte[] { 0x04, 0x80 })]
        [InlineData(new byte[] { 0x04, 0x81, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef })] // The length shall be encoded in the minimum number of octets
        [InlineData(new byte[] { 0x04, 0x82, 0x00, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef })] // The length shall be encoded in the minimum number of octets
        public static void OctetStringInvalid(byte[] value)
        {
            var reader = new Asn1Reader(value);
            Assert.Equal(new byte[0], reader.OctetString().ToArray());
            Assert.False(reader.Success);
            Assert.False(reader.SuccessComplete);
        }

        [Fact]
        public static void SequenceStackOverflow()
        {
            Assert.Equal(7, Asn1Reader.MaxDepth);
            var value = new byte[] { 0x30, 0x14, 0x30, 0x12, 0x30, 0x10, 0x30, 0x0E, 0x30, 0x0C, 0x30, 0x0A, 0x30, 0x08, 0x30, 0x06, 0x30, 0x04, 0x30, 0x02, 0x30, 0x00 };
            var reader = new Asn1Reader(value);
            reader.BeginSequence();
            Assert.True(reader.Success);
            reader.BeginSequence();
            Assert.True(reader.Success);
            reader.BeginSequence();
            Assert.True(reader.Success);
            reader.BeginSequence();
            Assert.True(reader.Success);
            reader.BeginSequence();
            Assert.True(reader.Success);
            reader.BeginSequence();
            Assert.True(reader.Success);
            try { reader.BeginSequence(); Assert.True(false); } catch (IndexOutOfRangeException) { } // cannot use Assert.Throws
        }

        [Fact]
        public static void SequenceStackUnderflow()
        {
            var value = new byte[0];
            var reader = new Asn1Reader(value);
            try { reader.End(); Assert.True(false); } catch (IndexOutOfRangeException) { } // cannot use Assert.Throws
        }

        [Fact]
        public static void SequenceGraceful()
        {
            var value = new byte[] { 0x30, 0x06, 0x30, 0x04, 0x30, 0x02, 0x30, 0x00 };
            var reader = new Asn1Reader(value);
            reader.BeginSequence();
            Assert.True(reader.Success);
            reader.BeginSequence();
            Assert.True(reader.Success);
            Assert.Equal(0, reader.Integer32());
            Assert.False(reader.Success);
            reader.End();
            Assert.False(reader.Success);
            reader.End();
            Assert.False(reader.Success);
            Assert.False(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(1, new byte[] { 0x30, 0x00 })]
        [InlineData(2, new byte[] { 0x30, 0x02, 0x30, 0x00 })]
        [InlineData(3, new byte[] { 0x30, 0x04, 0x30, 0x02, 0x30, 0x00 })]
        [InlineData(4, new byte[] { 0x30, 0x06, 0x30, 0x04, 0x30, 0x02, 0x30, 0x00 })]
        public static void Sequence(int depth, byte[] value)
        {
            var reader = new Asn1Reader(value);
            for (var i = 0; i < depth; i++)
            {
                reader.BeginSequence();
                Assert.True(reader.Success);
            }
            for (var i = 0; i < depth; i++)
            {
                reader.End();
                Assert.True(reader.Success);
            }
            Assert.True(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x30, 0x00 }, new int[] { })]
        [InlineData(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }, new int[] { 1 })]
        [InlineData(new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 }, new int[] { 1, 2 })]
        [InlineData(new byte[] { 0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03 }, new int[] { 1, 2, 3 })]
        public static void IntegerSequence(byte[] value, int[] expected)
        {
            var reader = new Asn1Reader(value);
            reader.BeginSequence();
            for (var i = 0; i < expected.Length; i++)
            {
                Assert.Equal(expected[i], reader.Integer32());
            }
            reader.End();
            Assert.True(reader.Success);
            Assert.True(reader.SuccessComplete);
        }

        [Theory]
        [InlineData(new byte[] { 0x30 })]
        [InlineData(new byte[] { 0x30, 0x01 })]
        [InlineData(new byte[] { 0x30, 0x80 })]
        [InlineData(new byte[] { 0x30, 0x81, 0x00 })]
        [InlineData(new byte[] { 0x30, 0x81, 0x01, 0xFF })]
        [InlineData(new byte[] { 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF })]
        [InlineData(new byte[] { 0x10, 0x00 })]
        public static void SequenceInvalid(byte[] value)
        {
            var reader = new Asn1Reader(value);
            reader.BeginSequence();
            Assert.False(reader.Success);
            Assert.False(reader.SuccessComplete);
        }

        [Fact]
        public static void InnerLengthGreaterThanOuterLength()
        {
            var value = new byte[] { 0x30, 0x08, 0x04, 0x0A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA };
            var reader = new Asn1Reader(value);
            reader.BeginSequence();
            Assert.True(reader.Success);
            Assert.Equal(new byte[0], reader.OctetString().ToArray());
            Assert.False(reader.Success);
            reader.End();
            Assert.False(reader.Success);
            Assert.False(reader.SuccessComplete);
        }

        [Fact]
        public static void UnexpectedDataAfterEnd1()
        {
            var value = new byte[] { 0x30, 0x03, 0x02, 0x01, 0x17, 0x02, 0x01, 0x42 };
            var reader = new Asn1Reader(value);
            reader.BeginSequence();
            Assert.True(reader.Success);
            Assert.Equal(0x17, reader.Integer32());
            Assert.True(reader.Success);
            reader.End();
            Assert.True(reader.Success);
            Assert.False(reader.SuccessComplete);
        }

        [Fact]
        public static void UnexpectedDataAfterEnd2()
        {
            var value = new byte[] { 0x30, 0x06, 0x02, 0x01, 0x17, 0x02, 0x01, 0x42 };
            var reader = new Asn1Reader(value);
            reader.BeginSequence();
            Assert.True(reader.Success);
            Assert.Equal(0x17, reader.Integer32());
            Assert.True(reader.Success);
            reader.End();
            Assert.False(reader.Success);
            Assert.False(reader.SuccessComplete);
        }
    }
}
