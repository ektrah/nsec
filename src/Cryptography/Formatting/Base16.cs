using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography.Formatting
{
    // RFC 4648
    public static class Base16
    {
        public static byte[] Decode(
            string base16)
        {
            if (!TryGetDecodedLength(base16, out int length))
            {
                throw Error.Format_BadBase16();
            }
            byte[] result = new byte[length];
            if (!TryDecode(base16, result))
            {
                throw Error.Format_BadBase16();
            }
            return result;
        }

        public static byte[] Decode(
            ReadOnlySpan<char> base16)
        {
            if (!TryGetDecodedLength(base16, out int length))
            {
                throw Error.Format_BadBase16();
            }
            byte[] result = new byte[length];
            if (!TryDecode(base16, result))
            {
                throw Error.Format_BadBase16();
            }
            return result;
        }

        public static byte[] Decode(
            ReadOnlySpan<byte> base16)
        {
            if (!TryGetDecodedLength(base16, out int length))
            {
                throw Error.Format_BadBase16();
            }
            byte[] result = new byte[length];
            if (!TryDecode(base16, result))
            {
                throw Error.Format_BadBase16();
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
            Span<char> base16)
        {
            if (base16.Length != GetEncodedLength(bytes.Length))
            {
                throw Error.Argument_BadBase16Length(nameof(base16));
            }
            if (bytes.IsEmpty)
            {
                return;
            }

            int di = 0;
            int si = 0;
            int b0, b1;

            while (bytes.Length - si >= 1)
            {
                EncodeByte(bytes[si++], out b0, out b1);
                base16[di++] = (char)b0;
                base16[di++] = (char)b1;
            }

            Debug.Assert(si == bytes.Length);
            Debug.Assert(di == base16.Length);
        }

        public static void Encode(
            ReadOnlySpan<byte> bytes,
            Span<byte> base16)
        {
            if (base16.Length != GetEncodedLength(bytes.Length))
            {
                throw Error.Argument_BadBase16Length(nameof(base16));
            }
            if (bytes.IsEmpty)
            {
                return;
            }

            int di = 0;
            int si = 0;
            int b0, b1;

            while (bytes.Length - si >= 1)
            {
                EncodeByte(bytes[si++], out b0, out b1);
                base16[di++] = (byte)b0;
                base16[di++] = (byte)b1;
            }

            Debug.Assert(si == bytes.Length);
            Debug.Assert(di == base16.Length);
        }

        public static int GetEncodedLength(
            int byteCount)
        {
            return byteCount * 2;
        }

        public static bool TryDecode(
            string base16,
            Span<byte> bytes)
        {
            if (base16 == null)
            {
                throw Error.ArgumentNull_String(nameof(base16));
            }

            return TryDecode(base16.AsReadOnlySpan(), bytes);
        }

        public static bool TryDecode(
            ReadOnlySpan<char> base16,
            Span<byte> bytes)
        {
            if (base16.Length != GetEncodedLength(bytes.Length))
            {
                throw Error.Argument_BadBase16Length(nameof(base16));
            }
            if (base16.IsEmpty)
            {
                return true;
            }

            int err = 0;
            int di = 0;
            int si = 0;
            byte r0;

            while (bytes.Length - di >= 1)
            {
                err |= DecodeByte(base16[si++], base16[si++], out r0);
                bytes[di++] = r0;
            }

            Debug.Assert(si == base16.Length);
            Debug.Assert(di == bytes.Length);

            return err == 0;
        }

        public static bool TryDecode(
            ReadOnlySpan<byte> base16,
            Span<byte> bytes)
        {
            if (base16.Length != GetEncodedLength(bytes.Length))
            {
                throw Error.Argument_BadBase16Length(nameof(base16));
            }
            if (base16.IsEmpty)
            {
                return true;
            }

            int err = 0;
            int di = 0;
            int si = 0;
            byte r0;

            while (bytes.Length - di >= 1)
            {
                err |= DecodeByte(base16[si++], base16[si++], out r0);
                bytes[di++] = r0;
            }

            Debug.Assert(si == base16.Length);
            Debug.Assert(di == bytes.Length);

            return err == 0;
        }

        public static bool TryGetDecodedLength(
            string base16,
            out int decodedLength)
        {
            if (base16 == null)
            {
                throw Error.ArgumentNull_String(nameof(base16));
            }

            return TryGetDecodedLength(base16.AsReadOnlySpan(), out decodedLength);
        }

        public static bool TryGetDecodedLength(
            ReadOnlySpan<char> base16,
            out int decodedLength)
        {
            if ((base16.Length & 1) != 0)
            {
                decodedLength = 0;
                return false;
            }

            decodedLength = base16.Length / 2;
            return true;
        }

        public static bool TryGetDecodedLength(
            ReadOnlySpan<byte> base16,
            out int decodedLength)
        {
            if ((base16.Length & 1) != 0)
            {
                decodedLength = 0;
                return false;
            }

            decodedLength = base16.Length / 2;
            return true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int Decode4Bits(
            int src)
        {
            unchecked
            {
                int ret = -1;
                ret += (((0x2f - src) & (src - 0x3a)) >> 31) & (src - 47);
                ret += (((0x40 - src) & (src - 0x47)) >> 31) & (src - 54);
                ret += (((0x60 - src) & (src - 0x67)) >> 31) & (src - 86);
                return ret;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int DecodeByte(
            int b0,
            int b1,
            out byte r0)
        {
            unchecked
            {
                int c0 = Decode4Bits(b0);
                int c1 = Decode4Bits(b1);

                r0 = (byte)((c0 << 4) | c1);

                return (c0 | c1) >> 31;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int Encode4Bits(
            int src)
        {
            unchecked
            {
                // upper case
                int diff = 48;
                diff += ((9 - src) >> 31) & 7;
                return src + diff;

                // lower case
                ////int diff = 48;
                ////diff += ((9 - src) >> 31) & 39;
                ////return src + diff;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void EncodeByte(
            byte b0,
            out int r0,
            out int r1)
        {
            unchecked
            {
                r0 = Encode4Bits(b0 >> 4);
                r1 = Encode4Bits(b0 & 15);
            }
        }
    }
}
