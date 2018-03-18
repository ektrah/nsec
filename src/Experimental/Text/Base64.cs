using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using NSec.Cryptography;

namespace NSec.Experimental.Text
{
    // RFC 4648
    public static class Base64
    {
        public static byte[] Decode(
            string base64)
        {
            if (!TryGetDecodedLength(base64, out int length))
            {
                throw Error.Format_BadBase64();
            }
            byte[] result = new byte[length];
            if (!TryDecode(base64, result))
            {
                throw Error.Format_BadBase64();
            }
            return result;
        }

        public static byte[] Decode(
            ReadOnlySpan<char> base64)
        {
            if (!TryGetDecodedLength(base64, out int length))
            {
                throw Error.Format_BadBase64();
            }
            byte[] result = new byte[length];
            if (!TryDecode(base64, result))
            {
                throw Error.Format_BadBase64();
            }
            return result;
        }

        public static byte[] DecodeUtf8(
            ReadOnlySpan<byte> base64)
        {
            if (!TryGetDecodedLength(base64, out int length))
            {
                throw Error.Format_BadBase64();
            }
            byte[] result = new byte[length];
            if (!TryDecodeUtf8(base64, result))
            {
                throw Error.Format_BadBase64();
            }
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
            Span<char> base64)
        {
            if (base64.Length != GetEncodedLength(bytes.Length))
            {
                throw Error.Argument_BadBase64Length(nameof(base64));
            }

            int di = 0;
            int si = 0;
            int b0, b1, b2, b3;

            while (bytes.Length - si >= 3)
            {
                Encode3Bytes(bytes[si++], bytes[si++], bytes[si++], out b0, out b1, out b2, out b3);
                base64[di++] = (char)b0;
                base64[di++] = (char)b1;
                base64[di++] = (char)b2;
                base64[di++] = (char)b3;
            }

            switch (bytes.Length - si)
            {
            case 1:
                Encode3Bytes(bytes[si++], 0, 0, out b0, out b1, out b2, out b3);
                base64[di++] = (char)b0;
                base64[di++] = (char)b1;
                base64[di++] = '=';
                base64[di++] = '=';
                break;

            case 2:
                Encode3Bytes(bytes[si++], bytes[si++], 0, out b0, out b1, out b2, out b3);
                base64[di++] = (char)b0;
                base64[di++] = (char)b1;
                base64[di++] = (char)b2;
                base64[di++] = '=';
                break;
            }

            Debug.Assert(si == bytes.Length);
            Debug.Assert(di == base64.Length);
        }

        public static void EncodeUtf8(
            ReadOnlySpan<byte> bytes,
            Span<byte> base64)
        {
            if (base64.Length != GetEncodedLength(bytes.Length))
            {
                throw Error.Argument_BadBase64Length(nameof(base64));
            }

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

        public static int GetEncodedLength(
            int byteCount)
        {
            return ((byteCount + 3 - 1) / 3) * 4;
        }

        public static bool TryDecode(
            string base64,
            Span<byte> bytes)
        {
            if (base64 == null)
            {
                throw Error.ArgumentNull_String(nameof(base64));
            }

            return TryDecode(base64.AsSpan(), bytes);
        }

        public static bool TryDecode(
            ReadOnlySpan<char> base64,
            Span<byte> bytes)
        {
            if (base64.Length != GetEncodedLength(bytes.Length))
            {
                throw Error.Argument_BadBase64Length(nameof(base64));
            }

            int err = 0;
            int di = 0;
            int si = 0;
            byte r0, r1, r2;

            while (bytes.Length - di >= 3)
            {
                err |= Decode3Bytes(base64[si++], base64[si++], base64[si++], base64[si++], out r0, out r1, out r2);
                bytes[di++] = r0;
                bytes[di++] = r1;
                bytes[di++] = r2;
            }

            switch (bytes.Length - di)
            {
            case 1:
                err |= Decode3Bytes(base64[si++], base64[si++], 'A', 'A', out r0, out r1, out r2);
                err |= CheckPadding(base64[si++]);
                err |= CheckPadding(base64[si++]);
                bytes[di++] = r0;
                break;

            case 2:
                err |= Decode3Bytes(base64[si++], base64[si++], base64[si++], 'A', out r0, out r1, out r2);
                err |= CheckPadding(base64[si++]);
                bytes[di++] = r0;
                bytes[di++] = r1;
                break;
            }

            Debug.Assert(si == base64.Length);
            Debug.Assert(di == bytes.Length);

            return err == 0;
        }

        public static bool TryDecodeUtf8(
            ReadOnlySpan<byte> base64,
            Span<byte> bytes)
        {
            if (base64.Length != GetEncodedLength(bytes.Length))
            {
                throw Error.Argument_BadBase64Length(nameof(base64));
            }

            int err = 0;
            int di = 0;
            int si = 0;
            byte r0, r1, r2;

            while (bytes.Length - di >= 3)
            {
                err |= Decode3Bytes(base64[si++], base64[si++], base64[si++], base64[si++], out r0, out r1, out r2);
                bytes[di++] = r0;
                bytes[di++] = r1;
                bytes[di++] = r2;
            }

            switch (bytes.Length - di)
            {
            case 1:
                err |= Decode3Bytes(base64[si++], base64[si++], 'A', 'A', out r0, out r1, out r2);
                err |= CheckPadding(base64[si++]);
                err |= CheckPadding(base64[si++]);
                bytes[di++] = r0;
                break;

            case 2:
                err |= Decode3Bytes(base64[si++], base64[si++], base64[si++], 'A', out r0, out r1, out r2);
                err |= CheckPadding(base64[si++]);
                bytes[di++] = r0;
                bytes[di++] = r1;
                break;
            }

            Debug.Assert(si == base64.Length);
            Debug.Assert(di == bytes.Length);

            return err == 0;
        }

        public static bool TryGetDecodedLength(
            string base64,
            out int decodedLength)
        {
            if (base64 == null)
            {
                throw Error.ArgumentNull_String(nameof(base64));
            }

            return TryGetDecodedLength(base64.AsSpan(), out decodedLength);
        }

        public static bool TryGetDecodedLength(
            ReadOnlySpan<char> base64,
            out int decodedLength)
        {
            if ((base64.Length & 3) != 0)
            {
                decodedLength = 0;
                return false;
            }

            int padding = 0;
            if (base64.Length != 0 && base64[base64.Length - 1] == '=')
            {
                padding++;
                if (base64[base64.Length - 2] == '=')
                {
                    padding++;
                }
            }

            decodedLength = (base64.Length / 4) * 3 - padding;
            return true;
        }

        public static bool TryGetDecodedLength(
            ReadOnlySpan<byte> base64,
            out int decodedLength)
        {
            if ((base64.Length & 3) != 0)
            {
                decodedLength = 0;
                return false;
            }

            int padding = 0;
            if (base64.Length != 0 && base64[base64.Length - 1] == '=')
            {
                padding++;
                if (base64[base64.Length - 2] == '=')
                {
                    padding++;
                }
            }

            decodedLength = (base64.Length / 4) * 3 - padding;
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
        private static int Decode3Bytes(
            int b0,
            int b1,
            int b2,
            int b3,
            out byte r0,
            out byte r1,
            out byte r2)
        {
            unchecked
            {
                int c0 = Decode6Bits(b0);
                int c1 = Decode6Bits(b1);
                int c2 = Decode6Bits(b2);
                int c3 = Decode6Bits(b3);

                r0 = (byte)(c0 << 2 | c1 >> 4);
                r1 = (byte)(c1 << 4 | c2 >> 2);
                r2 = (byte)(c2 << 6 | c3);

                return (c0 | c1 | c2 | c3) >> 31;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int Decode6Bits(
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
