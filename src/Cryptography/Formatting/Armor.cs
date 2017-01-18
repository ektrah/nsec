using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography.Formatting
{
    // RFC 7468
    // RFC 4648
    internal static class Armor
    {
        private static readonly byte[] s_decodingMap =
        {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F,
            0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
            0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        };

        private static readonly byte[] s_encodingMap =
        {
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
            0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
            0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
            0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
            0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2B, 0x2F,
        };

        private static readonly byte[] s_fiveHyphens =
        {
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D,
        };

        public static void Encode(
            ReadOnlySpan<byte> input,
            ReadOnlySpan<byte> beginLabel,
            ReadOnlySpan<byte> endLabel,
            Span<byte> output)
        {
            Debug.Assert(output.Length == GetEncodedSize(input.Length, beginLabel, endLabel));

            beginLabel.CopyTo(output);
            output[beginLabel.Length + 0] = (byte)'\r';
            output[beginLabel.Length + 1] = (byte)'\n';

            EncodeBase64(input, output.Slice(beginLabel.Length + 2));

            endLabel.CopyTo(output.Slice(output.Length - 2 - endLabel.Length));
            output[output.Length - 2] = (byte)'\r';
            output[output.Length - 1] = (byte)'\n';
        }

        public static int GetEncodedSize(
            int inputLength,
            ReadOnlySpan<byte> beginLabel,
            ReadOnlySpan<byte> endLabel)
        {
            int base64Length = ((inputLength + 3 - 1) / 3) * 4;
            base64Length += ((base64Length + 64 - 1) / 64) * 2;

            return
                beginLabel.Length + 2 +
                base64Length +
                endLabel.Length + 2;
        }

        public static bool TryDecode(
            ReadOnlySpan<byte> input,
            ReadOnlySpan<byte> beginLabel,
            ReadOnlySpan<byte> endLabel,
            Span<byte> output)
        {
            int i = input.IndexOf(s_fiveHyphens);
            if ((i < 0) || (input.Length - i < beginLabel.Length) || !input.Slice(i, beginLabel.Length).SequenceEqual(beginLabel))
            {
                return false;
            }

            input = input.Slice(i + beginLabel.Length);

            i = DecodeBase64(input, output);
            if ((i < 0) || (input.Length - i < endLabel.Length) || !input.Slice(i, endLabel.Length).SequenceEqual(endLabel))
            {
                return false;
            }

            return true;
        }

        private static void EncodeBase64(
            ReadOnlySpan<byte> input,
            Span<byte> output)
        {
            byte b0, b1, b2, b3;

            int i = 0;
            int j = 0;

            while (input.Length - i >= 3)
            {
                Encode(input[i + 0], input[i + 1], input[i + 2], out b0, out b1, out b2, out b3);

                output[j + 0] = b0;
                output[j + 1] = b1;
                output[j + 2] = b2;
                output[j + 3] = b3;

                i += 3;
                j += 4;

                if ((i % 48) == 0)
                {
                    output[j + 0] = (byte)'\r';
                    output[j + 1] = (byte)'\n';

                    j += 2;
                }
            }

            switch (input.Length - i)
            {
            case 2:
                Encode(input[i + 0], input[i + 1], 0, out b0, out b1, out b2, out b3);

                output[j + 0] = b0;
                output[j + 1] = b1;
                output[j + 2] = b2;
                output[j + 3] = (byte)'=';
                output[j + 4] = (byte)'\r';
                output[j + 5] = (byte)'\n';
                break;

            case 1:
                Encode(input[i + 0], 0, 0, out b0, out b1, out b2, out b3);

                output[j + 0] = b0;
                output[j + 1] = b1;
                output[j + 2] = (byte)'=';
                output[j + 3] = (byte)'=';
                output[j + 4] = (byte)'\r';
                output[j + 5] = (byte)'\n';
                break;

            case 0:
                if ((i % 48) != 0)
                {
                    output[j + 0] = (byte)'\r';
                    output[j + 1] = (byte)'\n';
                }
                break;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Encode(byte b0, byte b1, byte b2, out byte r0, out byte r1, out byte r2, out byte r3)
        {
            r0 = s_encodingMap[b0 >> 2];
            r1 = s_encodingMap[(b0 & 0x3) << 4 | (b1 >> 4)];
            r2 = s_encodingMap[(b1 & 0xF) << 2 | (b2 >> 6)];
            r3 = s_encodingMap[b2 & 0x3F];
        }

        private static int DecodeBase64(
            ReadOnlySpan<byte> input,
            Span<byte> output)
        {
            int buffer = 0;
            int filled = 0;
            int i = 0;
            int j = 0;

            while (i < input.Length)
            {
                int ch = input[i];
                if (ch == '=' || ch == '-')
                {
                    break;
                }
                i++;
                if (ch == ' ' || ch >= '\t' && ch <= '\r')
                {
                    continue;
                }
                int digit;
                if (ch >= 128 || (digit = s_decodingMap[ch]) == 0xFF)
                {
                    return -1;
                }
                buffer = (buffer << 6) | digit;
                filled += 6;
                if (filled >= 8)
                {
                    if (j == output.Length)
                    {
                        return -1;
                    }
                    output[j] = (byte)((buffer >> (filled - 8)) & 0xFF);
                    filled -= 8;
                    j++;
                }
            }

            while (i < input.Length)
            {
                int ch = input[i];
                if (ch == '-')
                {
                    break;
                }
                i++;
                if (ch == '=' || ch == ' ' || ch >= '\t' && ch <= '\r')
                {
                    continue;
                }
                return -1;
            }

            if (j != output.Length)
            {
                return -1;
            }

            return i;
        }
    }
}
