using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography.Formatting
{
    // RFC 4648
    internal static class Base64
    {
        public static void Encode(
            ReadOnlySpan<byte> bytes,
            Span<byte> base64)
        {
            Debug.Assert(base64.Length == GetEncodedLength(bytes.Length));
            Debug.Assert(!bytes.IsEmpty);

            unchecked
            {
                int di = 0;
                int si = 0;
                int b0, b1, b2, b3;

                while (bytes.Length - si >= 3)
                {
                    Encode3Bytes(bytes[si++], bytes[si++], bytes[si++], out b0, out b1, out b2, out b3);
                    base64[di++] = (byte)b0;
                    base64[di++] = (byte)b1;
                    base64[di++] = (byte)b2;
                    base64[di++] = (byte)b3;
                }

                switch (bytes.Length - si)
                {
                case 1:
                    Encode3Bytes(bytes[si++], 0, 0, out b0, out b1, out b2, out b3);
                    base64[di++] = (byte)b0;
                    base64[di++] = (byte)b1;
                    base64[di++] = (byte)'=';
                    base64[di++] = (byte)'=';
                    break;

                case 2:
                    Encode3Bytes(bytes[si++], bytes[si++], 0, out b0, out b1, out b2, out b3);
                    base64[di++] = (byte)b0;
                    base64[di++] = (byte)b1;
                    base64[di++] = (byte)b2;
                    base64[di++] = (byte)'=';
                    break;
                }

                Debug.Assert(si == bytes.Length);
                Debug.Assert(di == base64.Length);
            }
        }

        public static int GetEncodedLength(
            int byteCount)
        {
            return ((byteCount + 3 - 1) / 3) * 4;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static int Decode6Bits(
            int src)
        {
            unchecked
            {
                int ret = -1;
                ret += (((0x40 - src) & (src - 0x5b)) >> 31) & (src - 64);
                ret += (((0x60 - src) & (src - 0x7b)) >> 31) & (src - 70);
                ret += (((0x2f - src) & (src - 0x3a)) >> 31) & (src + 5);
                ret += (((0x2a - src) & (src - 0x2c)) >> 31) & 63;
                ret += (((0x2e - src) & (src - 0x30)) >> 31) & 64;
                return ret;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Encode3Bytes(
            byte b0,
            byte b1,
            byte b2,
            out int r0,
            out int r1,
            out int r2,
            out int r3)
        {
            unchecked
            {
                r0 = Encode6Bits(b0 >> 2);
                r1 = Encode6Bits((b0 << 4) & 63 | (b1 >> 4));
                r2 = Encode6Bits((b1 << 2) & 63 | (b2 >> 6));
                r3 = Encode6Bits(b2 & 63);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int Encode6Bits(
            int src)
        {
            unchecked
            {
                int diff = 65;
                diff += ((25 - src) >> 31) & 6;
                diff -= ((51 - src) >> 31) & 75;
                diff -= ((61 - src) >> 31) & 15;
                diff += ((62 - src) >> 31) & 3;
                return src + diff;
            }
        }
    }
}
