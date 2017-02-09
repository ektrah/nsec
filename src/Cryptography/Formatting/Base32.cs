using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography.Formatting
{
    // RFC 4648
    public static class Base32
    {
        public static byte[] Decode(
            string base32)
        {
            if (!TryGetDecodedLength(base32, out int length))
                throw new FormatException();
            byte[] result = new byte[length];
            if (!TryDecode(base32, result))
                throw new FormatException();
            return result;
        }

        public static byte[] Decode(
            ReadOnlySpan<char> base32)
        {
            if (!TryGetDecodedLength(base32, out int length))
                throw new FormatException();
            byte[] result = new byte[length];
            if (!TryDecode(base32, result))
                throw new FormatException();
            return result;
        }

        public static byte[] Decode(
            ReadOnlySpan<byte> base32)
        {
            if (!TryGetDecodedLength(base32, out int length))
                throw new FormatException();
            byte[] result = new byte[length];
            if (!TryDecode(base32, result))
                throw new FormatException();
            return result;
        }

        public static string Encode(
            ReadOnlySpan<byte> bytes)
        {
            char[] chars = new char[GetEncodedLength(bytes.Length)];
            Encode(bytes, chars);
            return new string(chars);
        }

        public static void Encode(
            ReadOnlySpan<byte> bytes,
            Span<char> base32)
        {
            if (base32.Length != GetEncodedLength(bytes.Length))
                throw new ArgumentException();
            if (bytes.IsEmpty)
                return;

            unchecked
            {
                int di = 0;
                int si = 0;
                int b0, b1, b2, b3, b4, b5, b6, b7;

                while (bytes.Length - si >= 5)
                {
                    Encode5Bytes(bytes[si++], bytes[si++], bytes[si++], bytes[si++], bytes[si++], out b0, out b1, out b2, out b3, out b4, out b5, out b6, out b7);
                    base32[di++] = (char)b0;
                    base32[di++] = (char)b1;
                    base32[di++] = (char)b2;
                    base32[di++] = (char)b3;
                    base32[di++] = (char)b4;
                    base32[di++] = (char)b5;
                    base32[di++] = (char)b6;
                    base32[di++] = (char)b7;
                }

                switch (bytes.Length - si)
                {
                case 1:
                    Encode5Bytes(bytes[si++], 0, 0, 0, 0, out b0, out b1, out b2, out b3, out b4, out b5, out b6, out b7);
                    base32[di++] = (char)b0;
                    base32[di++] = (char)b1;
                    base32[di++] = '=';
                    base32[di++] = '=';
                    base32[di++] = '=';
                    base32[di++] = '=';
                    base32[di++] = '=';
                    base32[di++] = '=';
                    break;

                case 2:
                    Encode5Bytes(bytes[si++], bytes[si++], 0, 0, 0, out b0, out b1, out b2, out b3, out b4, out b5, out b6, out b7);
                    base32[di++] = (char)b0;
                    base32[di++] = (char)b1;
                    base32[di++] = (char)b2;
                    base32[di++] = (char)b3;
                    base32[di++] = '=';
                    base32[di++] = '=';
                    base32[di++] = '=';
                    base32[di++] = '=';
                    break;

                case 3:
                    Encode5Bytes(bytes[si++], bytes[si++], bytes[si++], 0, 0, out b0, out b1, out b2, out b3, out b4, out b5, out b6, out b7);
                    base32[di++] = (char)b0;
                    base32[di++] = (char)b1;
                    base32[di++] = (char)b2;
                    base32[di++] = (char)b3;
                    base32[di++] = (char)b4;
                    base32[di++] = '=';
                    base32[di++] = '=';
                    base32[di++] = '=';
                    break;

                case 4:
                    Encode5Bytes(bytes[si++], bytes[si++], bytes[si++], bytes[si++], 0, out b0, out b1, out b2, out b3, out b4, out b5, out b6, out b7);
                    base32[di++] = (char)b0;
                    base32[di++] = (char)b1;
                    base32[di++] = (char)b2;
                    base32[di++] = (char)b3;
                    base32[di++] = (char)b4;
                    base32[di++] = (char)b5;
                    base32[di++] = (char)b6;
                    base32[di++] = '=';
                    break;
                }

                Debug.Assert(si == bytes.Length);
                Debug.Assert(di == base32.Length);
            }
        }

        public static void Encode(
            ReadOnlySpan<byte> bytes,
            Span<byte> base32)
        {
            if (base32.Length != GetEncodedLength(bytes.Length))
                throw new ArgumentException();
            if (bytes.IsEmpty)
                return;

            unchecked
            {
                int di = 0;
                int si = 0;
                int b0, b1, b2, b3, b4, b5, b6, b7;

                while (bytes.Length - si >= 5)
                {
                    Encode5Bytes(bytes[si++], bytes[si++], bytes[si++], bytes[si++], bytes[si++], out b0, out b1, out b2, out b3, out b4, out b5, out b6, out b7);
                    base32[di++] = (byte)b0;
                    base32[di++] = (byte)b1;
                    base32[di++] = (byte)b2;
                    base32[di++] = (byte)b3;
                    base32[di++] = (byte)b4;
                    base32[di++] = (byte)b5;
                    base32[di++] = (byte)b6;
                    base32[di++] = (byte)b7;
                }

                switch (bytes.Length - si)
                {
                case 1:
                    Encode5Bytes(bytes[si++], 0, 0, 0, 0, out b0, out b1, out b2, out b3, out b4, out b5, out b6, out b7);
                    base32[di++] = (byte)b0;
                    base32[di++] = (byte)b1;
                    base32[di++] = (byte)'=';
                    base32[di++] = (byte)'=';
                    base32[di++] = (byte)'=';
                    base32[di++] = (byte)'=';
                    base32[di++] = (byte)'=';
                    base32[di++] = (byte)'=';
                    break;

                case 2:
                    Encode5Bytes(bytes[si++], bytes[si++], 0, 0, 0, out b0, out b1, out b2, out b3, out b4, out b5, out b6, out b7);
                    base32[di++] = (byte)b0;
                    base32[di++] = (byte)b1;
                    base32[di++] = (byte)b2;
                    base32[di++] = (byte)b3;
                    base32[di++] = (byte)'=';
                    base32[di++] = (byte)'=';
                    base32[di++] = (byte)'=';
                    base32[di++] = (byte)'=';
                    break;

                case 3:
                    Encode5Bytes(bytes[si++], bytes[si++], bytes[si++], 0, 0, out b0, out b1, out b2, out b3, out b4, out b5, out b6, out b7);
                    base32[di++] = (byte)b0;
                    base32[di++] = (byte)b1;
                    base32[di++] = (byte)b2;
                    base32[di++] = (byte)b3;
                    base32[di++] = (byte)b4;
                    base32[di++] = (byte)'=';
                    base32[di++] = (byte)'=';
                    base32[di++] = (byte)'=';
                    break;

                case 4:
                    Encode5Bytes(bytes[si++], bytes[si++], bytes[si++], bytes[si++], 0, out b0, out b1, out b2, out b3, out b4, out b5, out b6, out b7);
                    base32[di++] = (byte)b0;
                    base32[di++] = (byte)b1;
                    base32[di++] = (byte)b2;
                    base32[di++] = (byte)b3;
                    base32[di++] = (byte)b4;
                    base32[di++] = (byte)b5;
                    base32[di++] = (byte)b6;
                    base32[di++] = (byte)'=';
                    break;
                }

                Debug.Assert(si == bytes.Length);
                Debug.Assert(di == base32.Length);
            }
        }

        public static int GetEncodedLength(
            int byteCount)
        {
            return ((byteCount + 5 - 1) / 5) * 8;
        }

        public static bool TryDecode(
            string base32,
            Span<byte> bytes)
        {
            if (base32 == null)
                throw new ArgumentNullException(nameof(base32));

            return TryDecode(base32.Slice(), bytes);
        }

        public static bool TryDecode(
            ReadOnlySpan<char> base32,
            Span<byte> bytes)
        {
            if (base32.Length != GetEncodedLength(bytes.Length))
                throw new ArgumentException();
            if (base32.IsEmpty)
                return true;

            unchecked
            {
                int err = 0;
                int di = 0;
                int si = 0;
                byte r0, r1, r2, r3, r4;

                while (bytes.Length - di >= 5)
                {
                    err |= Decode5Bytes(base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], out r0, out r1, out r2, out r3, out r4);
                    bytes[di++] = r0;
                    bytes[di++] = r1;
                    bytes[di++] = r2;
                    bytes[di++] = r3;
                    bytes[di++] = r4;
                }

                switch (bytes.Length - di)
                {
                case 1:
                    err |= Decode5Bytes(base32[si++], base32[si++], 'A', 'A', 'A', 'A', 'A', 'A', out r0, out r1, out r2, out r3, out r4);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    bytes[di++] = r0;
                    break;

                case 2:
                    err |= Decode5Bytes(base32[si++], base32[si++], base32[si++], base32[si++], 'A', 'A', 'A', 'A', out r0, out r1, out r2, out r3, out r4);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    bytes[di++] = r0;
                    bytes[di++] = r1;
                    break;

                case 3:
                    err |= Decode5Bytes(base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], 'A', 'A', 'A', out r0, out r1, out r2, out r3, out r4);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    bytes[di++] = r0;
                    bytes[di++] = r1;
                    bytes[di++] = r2;
                    break;

                case 4:
                    err |= Decode5Bytes(base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], 'A', out r0, out r1, out r2, out r3, out r4);
                    err |= CheckPadding(base32[si++]);
                    bytes[di++] = r0;
                    bytes[di++] = r1;
                    bytes[di++] = r2;
                    bytes[di++] = r3;
                    break;
                }

                Debug.Assert(si == base32.Length);
                Debug.Assert(di == bytes.Length);

                return err == 0;
            }
        }

        public static bool TryDecode(
            ReadOnlySpan<byte> base32,
            Span<byte> bytes)
        {
            if (base32.Length != GetEncodedLength(bytes.Length))
                throw new ArgumentException();
            if (base32.IsEmpty)
                return true;

            unchecked
            {
                int err = 0;
                int di = 0;
                int si = 0;
                byte r0, r1, r2, r3, r4;

                while (bytes.Length - di >= 5)
                {
                    err |= Decode5Bytes(base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], out r0, out r1, out r2, out r3, out r4);
                    bytes[di++] = r0;
                    bytes[di++] = r1;
                    bytes[di++] = r2;
                    bytes[di++] = r3;
                    bytes[di++] = r4;
                }

                switch (bytes.Length - di)
                {
                case 1:
                    err |= Decode5Bytes(base32[si++], base32[si++], 'A', 'A', 'A', 'A', 'A', 'A', out r0, out r1, out r2, out r3, out r4);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    bytes[di++] = r0;
                    break;

                case 2:
                    err |= Decode5Bytes(base32[si++], base32[si++], base32[si++], base32[si++], 'A', 'A', 'A', 'A', out r0, out r1, out r2, out r3, out r4);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    bytes[di++] = r0;
                    bytes[di++] = r1;
                    break;

                case 3:
                    err |= Decode5Bytes(base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], 'A', 'A', 'A', out r0, out r1, out r2, out r3, out r4);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    err |= CheckPadding(base32[si++]);
                    bytes[di++] = r0;
                    bytes[di++] = r1;
                    bytes[di++] = r2;
                    break;

                case 4:
                    err |= Decode5Bytes(base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], base32[si++], 'A', out r0, out r1, out r2, out r3, out r4);
                    err |= CheckPadding(base32[si++]);
                    bytes[di++] = r0;
                    bytes[di++] = r1;
                    bytes[di++] = r2;
                    bytes[di++] = r3;
                    break;
                }

                Debug.Assert(si == base32.Length);
                Debug.Assert(di == bytes.Length);

                return err == 0;
            }
        }

        public static bool TryGetDecodedLength(
            string base32,
            out int decodedLength)
        {
            if (base32 == null)
                throw new ArgumentNullException(nameof(base32));

            return TryGetDecodedLength(base32.Slice(), out decodedLength);
        }

        public static bool TryGetDecodedLength(
            ReadOnlySpan<char> base32,
            out int decodedLength)
        {
            if ((base32.Length & 7) != 0)
            {
                decodedLength = 0;
                return false;
            }

            int padding = 0;
            if (base32.Length != 0 && base32[base32.Length - 1] == '=')
            {
                padding++;
                if (base32[base32.Length - 2] == '=' && base32[base32.Length - 3] == '=')
                {
                    padding++;
                    if (base32[base32.Length - 4] == '=')
                    {
                        padding++;
                        if (base32[base32.Length - 5] == '=' && base32[base32.Length - 6] == '=')
                        {
                            padding++;
                        }
                    }
                }
            }

            decodedLength = (base32.Length / 8) * 5 - padding;
            return true;
        }

        public static bool TryGetDecodedLength(
            ReadOnlySpan<byte> base32,
            out int decodedLength)
        {
            if ((base32.Length & 7) != 0)
            {
                decodedLength = 0;
                return false;
            }

            int padding = 0;
            if (base32.Length != 0 && base32[base32.Length - 1] == '=')
            {
                padding++;
                if (base32[base32.Length - 2] == '=' && base32[base32.Length - 3] == '=')
                {
                    padding++;
                    if (base32[base32.Length - 4] == '=')
                    {
                        padding++;
                        if (base32[base32.Length - 5] == '=' && base32[base32.Length - 6] == '=')
                        {
                            padding++;
                        }
                    }
                }
            }

            decodedLength = (base32.Length / 8) * 5 - padding;
            return true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int CheckPadding(
            int src)
        {
            unchecked
            {
                return ((0x3d - src) | (src - 0x3d)) >> 31;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int Decode5Bits(
            int src)
        {
            unchecked
            {
                int ret = -1;
                ret += (((0x40 - src) & (src - 0x5b)) >> 31) & (src - 64);
                ret += (((0x60 - src) & (src - 0x7b)) >> 31) & (src - 96);
                ret += (((0x31 - src) & (src - 0x38)) >> 31) & (src - 23);
                return ret;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int Decode5Bytes(
            int b0,
            int b1,
            int b2,
            int b3,
            int b4,
            int b5,
            int b6,
            int b7,
            out byte r0,
            out byte r1,
            out byte r2,
            out byte r3,
            out byte r4)
        {
            unchecked
            {
                int c0 = Decode5Bits(b0);
                int c1 = Decode5Bits(b1);
                int c2 = Decode5Bits(b2);
                int c3 = Decode5Bits(b3);
                int c4 = Decode5Bits(b4);
                int c5 = Decode5Bits(b5);
                int c6 = Decode5Bits(b6);
                int c7 = Decode5Bits(b7);

                r0 = (byte)(c0 << 3 | c1 >> 2);
                r1 = (byte)(c1 << 6 | c2 << 1 | c3 >> 4);
                r2 = (byte)(c3 << 4 | c4 >> 1);
                r3 = (byte)(c4 << 7 | c5 << 2 | c6 >> 3);
                r4 = (byte)(c6 << 5 | c7);

                return (c0 | c1 | c2 | c3 | c4 | c5 | c6 | c7) >> 31;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int Encode5Bits(
            int src)
        {
            unchecked
            {
                // upper case
                int diff = 65;
                diff -= ((25 - src) >> 31) & 41;
                return src + diff;

                // lower case
                ////int diff = 97;
                ////diff -= ((25 - src) >> 31) & 73;
                ////return src + diff;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Encode5Bytes(
            byte b0,
            byte b1,
            byte b2,
            byte b3,
            byte b4,
            out int r0,
            out int r1,
            out int r2,
            out int r3,
            out int r4,
            out int r5,
            out int r6,
            out int r7)
        {
            unchecked
            {
                r0 = Encode5Bits(b0 >> 3);
                r1 = Encode5Bits((b0 << 2) & 31 | (b1 >> 6));
                r2 = Encode5Bits((b1 >> 1) & 31);
                r3 = Encode5Bits((b1 << 4) & 31 | (b2 >> 4));
                r4 = Encode5Bits((b2 << 1) & 31 | (b3 >> 7));
                r5 = Encode5Bits((b3 >> 2) & 31);
                r6 = Encode5Bits((b3 << 3) & 31 | (b4 >> 5));
                r7 = Encode5Bits(b4 & 31);
            }
        }
    }
}
