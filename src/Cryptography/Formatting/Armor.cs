using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography.Formatting
{
    // RFC 7468
    internal static class Armor
    {
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
            int base64Length = Base64.GetEncodedLength(inputLength);
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
            return TryDecode(input, beginLabel, endLabel, output, out int bytesWritten) && (bytesWritten == output.Length);
        }

        public static bool TryDecode(
            ReadOnlySpan<byte> input,
            ReadOnlySpan<byte> beginLabel,
            ReadOnlySpan<byte> endLabel,
            Span<byte> output,
            out int bytesWritten)
        {
            int i = input.IndexOf(s_fiveHyphens);
            if ((i < 0) || (input.Length - i < beginLabel.Length) || !input.Slice(i, beginLabel.Length).SequenceEqual(beginLabel))
            {
                bytesWritten = 0;
                return false;
            }

            input = input.Slice(i + beginLabel.Length);

            i = DecodeBase64(input, output, out bytesWritten);
            if ((i < 0) || (input.Length - i < endLabel.Length) || !input.Slice(i, endLabel.Length).SequenceEqual(endLabel))
            {
                bytesWritten = 0;
                return false;
            }

            return true;
        }

        private static void EncodeBase64(
            ReadOnlySpan<byte> input,
            Span<byte> output)
        {
            int i = 0;
            int j = 0;

            while (input.Length - i >= 48)
            {
                Base64.Encode(input.Slice(i, 48), output.Slice(j, 64));
                j += 64;
                output[j + 0] = (byte)'\r';
                output[j + 1] = (byte)'\n';
                j += 2;
                i += 48;
            }

            if (input.Length - i > 0)
            {
                Base64.Encode(input.Slice(i), output.Slice(j));
                j += Base64.GetEncodedLength(input.Length - i);
                output[j + 0] = (byte)'\r';
                output[j + 1] = (byte)'\n';
            }
        }

        private static int DecodeBase64(
            ReadOnlySpan<byte> input,
            Span<byte> output,
            out int bytesWritten)
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
                int digit = Base64.Decode6Bits(ch);
                if (digit == -1)
                {
                    bytesWritten = 0;
                    return -1;
                }
                buffer = (buffer << 6) | digit;
                filled += 6;
                if (filled >= 8)
                {
                    if (j == output.Length)
                    {
                        bytesWritten = 0;
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
                bytesWritten = 0;
                return -1;
            }

            bytesWritten = j;
            return i;
        }
    }
}
