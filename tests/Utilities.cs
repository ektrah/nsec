using System;
using Xunit;

namespace NSec.Tests
{
    internal static class Utilities
    {
        public static ReadOnlySpan<byte> RandomBytes => s_randomBytes;

        public static T AssertNotNull<T>(T? obj) where T : class
        {
            Assert.NotNull(obj);
            return obj!;
        }

        public static byte[] DecodeHex(this string hex) => NSec.Experimental.Text.Base16.Decode(hex);

        public static string EncodeHex(this byte[] bytes) => NSec.Experimental.Text.Base16.Encode(bytes);

        public static byte[] FillArray(int length, byte value)
        {
            var array = new byte[length];
            array.AsSpan().Fill(value);
            return array;
        }

        public static byte[] Substring(this byte[] array, Range range) => array.AsSpan(range.Start.Value, range.End.Value - range.Start.Value).ToArray();

        #region Random Bytes

        private static readonly byte[] s_randomBytes =
        {
            0xfb, 0x2c, 0x66, 0x4c, 0x14, 0x40, 0x2b, 0x56, 0xae, 0xb5, 0x60, 0x1e, 0x68, 0x35, 0x8e, 0xeb,
            0x40, 0xa7, 0x9e, 0xcb, 0xe4, 0xd0, 0xb4, 0xf8, 0xf8, 0x45, 0x3f, 0xcc, 0x3c, 0xd0, 0x08, 0x04,
            0x04, 0x2e, 0x3d, 0x42, 0x88, 0x4f, 0x68, 0xf8, 0xa1, 0xae, 0x52, 0x8e, 0x7a, 0x1c, 0x3c, 0x43,
            0xbb, 0x07, 0xaf, 0xfd, 0x62, 0xf6, 0x00, 0x39, 0xd0, 0x2f, 0x6a, 0xca, 0xad, 0x01, 0x9e, 0x55,
            0xe4, 0x94, 0x22, 0x7e, 0xf0, 0x2c, 0x8f, 0xcd, 0xd6, 0x4f, 0x5e, 0x78, 0xd4, 0xdf, 0x52, 0xe3,
            0x55, 0x1d, 0x4e, 0x7c, 0x0e, 0x77, 0x22, 0x49, 0x60, 0x8b, 0xa1, 0x70, 0xb6, 0x6e, 0xf8, 0xa7,
            0x1b, 0x12, 0x3e, 0xb1, 0x54, 0x3c, 0x05, 0x82, 0x2d, 0x90, 0xfd, 0x62, 0x9f, 0xa0, 0x18, 0x8c,
            0xc6, 0x33, 0xde, 0x2a, 0x44, 0x75, 0x7e, 0xac, 0x83, 0x0a, 0x55, 0xdf, 0xfe, 0x34, 0x0f, 0x42,
            0x45, 0x00, 0xca, 0x75, 0x69, 0x0a, 0xb2, 0x87, 0x68, 0x4b, 0x06, 0xb4, 0x7c, 0xd5, 0x42, 0x72,
            0x0f, 0xfa, 0x31, 0xf5, 0x84, 0xdf, 0x85, 0x05, 0x1b, 0x2d, 0xcb, 0xb4, 0xc2, 0xc8, 0x74, 0x4b,
            0x1b, 0x1e, 0x3a, 0x02, 0x57, 0x4b, 0x29, 0x1b, 0x21, 0xab, 0xaa, 0x04, 0x41, 0x82, 0x28, 0x18,
            0xaa, 0x7a, 0x35, 0x3e, 0x8f, 0x32, 0xad, 0x3d, 0x58, 0x0d, 0x1d, 0xdb, 0xab, 0xd8, 0x98, 0x77,
            0xe1, 0xd4, 0x0b, 0xb0, 0x98, 0x45, 0x17, 0xec, 0xcc, 0x9c, 0xd8, 0x37, 0x57, 0x0e, 0x6f, 0x59,
            0xb3, 0x53, 0x5e, 0x0c, 0x34, 0x35, 0x1b, 0xaa, 0xf9, 0x7d, 0x89, 0x44, 0x96, 0x6a, 0x53, 0xd9,
            0xb4, 0xf9, 0xac, 0x53, 0xb1, 0x26, 0xa3, 0x58, 0x62, 0x00, 0x72, 0x79, 0x78, 0x4c, 0x4e, 0x06,
            0x30, 0x39, 0xbf, 0xaa, 0xbc, 0x49, 0xdb, 0x3c, 0xc9, 0x72, 0x3f, 0xf6, 0xce, 0x1b, 0xe9, 0x86,
            0x82, 0x82, 0x09, 0xab, 0xb5, 0xdc, 0xd8, 0x1c, 0x0e, 0x82, 0xd4, 0x2f, 0x78, 0x3f, 0xb9, 0x25,
            0x7b, 0x11, 0x10, 0x6e, 0x2b, 0x36, 0xea, 0xca, 0x61, 0xc9, 0xa7, 0x86, 0xa0, 0x12, 0xb9, 0xbc,
            0x07, 0x57, 0xa3, 0x05, 0xcb, 0xd7, 0x67, 0xfb, 0x0e, 0x87, 0x52, 0x1b, 0x6f, 0x60, 0x0a, 0x5b,
            0x89, 0x21, 0x35, 0xcf, 0x39, 0x3e, 0x2f, 0x97, 0x47, 0xf9, 0x5c, 0x60, 0xcd, 0xb5, 0x12, 0x2b,
            0x65, 0x92, 0x76, 0x17, 0x45, 0x29, 0x25, 0xd8, 0xf4, 0xb4, 0xc5, 0xb8, 0x4b, 0xe9, 0x3d, 0x91,
            0x1f, 0xa9, 0x6f, 0x65, 0x43, 0x9a, 0x43, 0xf6, 0x50, 0x97, 0xbd, 0x43, 0x66, 0xfe, 0x71, 0xbe,
            0xdc, 0x6a, 0xec, 0x64, 0x54, 0x28, 0xf2, 0xac, 0x83, 0x9a, 0x0d, 0xb6, 0x47, 0xc0, 0x95, 0xbb,
            0xc7, 0xaa, 0x9d, 0xa4, 0xd8, 0x32, 0xf8, 0xbd, 0x8e, 0x24, 0xfc, 0xd9, 0xaa, 0x08, 0x7c, 0x1b,
            0x03, 0x68, 0xc6, 0xde, 0x90, 0xe6, 0xc8, 0x2d, 0x2c, 0xe1, 0x4f, 0x30, 0x36, 0x6b, 0x89, 0x3e,
            0xe1, 0x02, 0xc8, 0xfe, 0x1c, 0xc9, 0x25, 0x86, 0x77, 0x34, 0x82, 0x0e, 0x50, 0xca, 0xa8, 0xc0,
            0x10, 0x89, 0x00, 0xb7, 0xa9, 0x5e, 0x82, 0xef, 0x02, 0x9a, 0xea, 0xa0, 0x47, 0x66, 0xe4, 0x51,
            0x19, 0xc2, 0x6b, 0x99, 0xdc, 0x1d, 0xe4, 0x7f, 0x59, 0x85, 0xe9, 0x21, 0x66, 0x94, 0xef, 0x01,
            0x54, 0x24, 0x56, 0x78, 0x32, 0xc4, 0x6a, 0x07, 0x51, 0xcb, 0x75, 0xb8, 0x98, 0xcf, 0x01, 0xb6,
            0x29, 0x89, 0xa2, 0xc8, 0x95, 0xf1, 0x52, 0xb9, 0xe6, 0x65, 0x84, 0xde, 0xf9, 0x5f, 0xbe, 0xf0,
            0x2c, 0x5e, 0x34, 0x14, 0x7e, 0xf3, 0x33, 0xe5, 0x36, 0x14, 0x36, 0x6a, 0xe9, 0xe8, 0x94, 0xd7,
            0xf7, 0xf2, 0xa2, 0xbd, 0x7c, 0xd4, 0x32, 0x3b, 0xa5, 0x6f, 0x97, 0x06, 0x2c, 0x82, 0xc7, 0x03,
            0x83, 0x2e, 0x60, 0xf4, 0x87, 0x5b, 0xfd, 0xe2, 0x75, 0x97, 0x15, 0x25, 0x1c, 0x8d, 0x40, 0xf6,
            0x8c, 0xd1, 0xaf, 0x6b, 0xd6, 0xc3, 0xa8, 0x6c, 0x6f, 0xc3, 0xfb, 0x1a, 0x4c, 0x75, 0xd1, 0x41,
            0x1a, 0x4e, 0x9a, 0x3a, 0x83, 0x9a, 0xf9, 0x55, 0xda, 0xaa, 0x43, 0x70, 0x14, 0x5b, 0x15, 0x14,
            0x75, 0xe7, 0xe3, 0x1b, 0x66, 0xab, 0x7b, 0xb6, 0xca, 0x8b, 0x31, 0xa4, 0xf8, 0x53, 0x0e, 0x72,
            0x8c, 0x43, 0x7e, 0x7d, 0x7b, 0x08, 0xef, 0x33, 0x4e, 0x27, 0x6c, 0xa7, 0x42, 0x0f, 0xbb, 0x25,
            0xeb, 0x01, 0x72, 0x01, 0x13, 0xdf, 0xd5, 0x29, 0x76, 0x08, 0xa0, 0xa4, 0xf6, 0x35, 0x49, 0xeb,
            0x7e, 0xd1, 0xa1, 0x70, 0x66, 0x54, 0xf9, 0xb4, 0xf3, 0xcf, 0x61, 0xcd, 0x60, 0xcd, 0xed, 0x75,
            0xa4, 0x25, 0x21, 0xbe, 0x62, 0xca, 0x61, 0x6b, 0x88, 0xcb, 0x5b, 0xfe, 0xe6, 0x06, 0x2c, 0x77,
            0xcd, 0xff, 0x21, 0xa2, 0x0a, 0xf4, 0x30, 0x31, 0xde, 0x45, 0xf7, 0x26, 0x04, 0x76, 0xf0, 0x8e,
            0x0c, 0xe0, 0xef, 0x53, 0x43, 0x04, 0x68, 0x63, 0x60, 0x36, 0x50, 0xaa, 0xb8, 0x4a, 0x9a, 0x66,
            0xb0, 0x08, 0xb1, 0xa4, 0xfa, 0x17, 0x9f, 0xb5, 0xf9, 0x08, 0xf6, 0xcd, 0x45, 0x8c, 0xce, 0x05,
            0x33, 0x7a, 0xd5, 0x95, 0x3f, 0xd4, 0x22, 0x04, 0x96, 0x10, 0x52, 0x99, 0xf6, 0x53, 0x41, 0xd7,
            0xfc, 0xc7, 0x73, 0x4c, 0x00, 0xcc, 0x2f, 0xf2, 0x70, 0x24, 0xd0, 0x3f, 0xe0, 0x34, 0x29, 0x3d,
            0x2e, 0xd1, 0xf0, 0x66, 0x9c, 0x5f, 0xac, 0xac, 0xf0, 0x29, 0x21, 0xd2, 0xeb, 0x38, 0xe6, 0xe9,
            0x07, 0xf1, 0xb8, 0x6c, 0x04, 0x65, 0x76, 0x63, 0x84, 0xc2, 0xb6, 0xfb, 0xd6, 0xdb, 0xbd, 0x28,
            0xc0, 0x83, 0xcd, 0xdb, 0x70, 0xa8, 0x3e, 0x7e, 0x76, 0xcb, 0x2b, 0x86, 0x34, 0xe1, 0xcc, 0xb0,
            0x22, 0x7b, 0xdf, 0x52, 0xc9, 0xe2, 0x8c, 0xc6, 0xf4, 0xc6, 0x98, 0xe0, 0xec, 0x4c, 0x7c, 0x4c,
            0x73, 0xf7, 0xb4, 0x41, 0x42, 0xd6, 0x0b, 0xf3, 0x5f, 0x79, 0x42, 0x36, 0x8c, 0xf6, 0xbf, 0x5c,
            0xd8, 0x52, 0x5b, 0x19, 0x02, 0xe5, 0x8a, 0xdf, 0x37, 0xf6, 0x88, 0x2e, 0x47, 0xe1, 0x4c, 0x38,
            0x4d, 0x82, 0xe4, 0x9d, 0xdc, 0x75, 0xe9, 0xca, 0x99, 0xfb, 0xe0, 0x80, 0xe3, 0x7d, 0xec, 0x36,
            0x71, 0xf4, 0xc9, 0xe7, 0xc6, 0xd9, 0x51, 0xa2, 0x89, 0x6f, 0xa8, 0x79, 0x99, 0xb8, 0x78, 0x8c,
            0x43, 0xb5, 0x62, 0xcb, 0xb9, 0xff, 0x86, 0xb8, 0xe9, 0xca, 0x98, 0x68, 0xc3, 0x49, 0xb7, 0xa0,
            0xea, 0xd4, 0x89, 0xef, 0xe3, 0x3d, 0xb9, 0x8b, 0x6b, 0xa9, 0x9e, 0x6b, 0xac, 0x24, 0x75, 0x29,
            0x18, 0xc9, 0xb6, 0x63, 0x6b, 0xf0, 0x14, 0x1d, 0x43, 0x1d, 0xde, 0x86, 0x23, 0x67, 0x19, 0xc1,
            0x52, 0xce, 0x23, 0xce, 0x81, 0x95, 0xc3, 0x20, 0x94, 0x57, 0xeb, 0xc1, 0x60, 0x5a, 0x05, 0xdd,
            0x79, 0xd9, 0x85, 0x44, 0x83, 0x6f, 0x8b, 0x20, 0x0c, 0xb5, 0x29, 0xe2, 0xad, 0x5c, 0x15, 0x7c,
            0x31, 0x48, 0x4c, 0x4d, 0xba, 0x97, 0xbf, 0xa5, 0x65, 0x02, 0x9d, 0x14, 0x4f, 0x11, 0x9c, 0x2a,
            0xda, 0xc9, 0x29, 0xad, 0x44, 0xac, 0xd4, 0x84, 0x87, 0x8e, 0xfd, 0x1d, 0xab, 0x51, 0x2e, 0xa7,
            0x07, 0x79, 0x30, 0x35, 0x5a, 0x79, 0xca, 0x13, 0x98, 0xc8, 0x15, 0xca, 0x0c, 0x17, 0x1f, 0xfb,
            0x91, 0xd5, 0x8b, 0x13, 0xa6, 0x7a, 0x3f, 0x6a, 0xa3, 0x2b, 0x1d, 0x32, 0x70, 0xf7, 0x89, 0x87,
            0xf2, 0x44, 0x2b, 0x42, 0x03, 0xaa, 0x62, 0x9f, 0x34, 0x5b, 0x7d, 0xb7, 0xd9, 0xb3, 0xcb, 0xb1,
            0x83, 0x83, 0x89, 0x86, 0x1d, 0x79, 0x17, 0x8e, 0x11, 0x50, 0x37, 0x5a, 0x27, 0xfe, 0x7f, 0x88,
        };

        #endregion
    }
}
