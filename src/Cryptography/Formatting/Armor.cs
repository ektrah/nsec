using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography.Formatting
{
    // RFC 7468
    internal static class Armor
    {
        public static void EncodeToUtf8(
            ReadOnlySpan<byte> bytes,
            ReadOnlySpan<byte> utf8BeginLabel,
            ReadOnlySpan<byte> utf8EndLabel,
            Span<byte> utf8)
        {
            Debug.Assert(utf8.Length == GetEncodedToUtf8Length(bytes.Length, utf8BeginLabel, utf8EndLabel));

            int remaining;
            int i = 0;
            int j = 0;

            utf8BeginLabel.CopyTo(utf8[j..]);
            j += utf8BeginLabel.Length;
            utf8[j++] = (byte)'\r';
            utf8[j++] = (byte)'\n';

            while ((remaining = bytes.Length - i) > 0)
            {
                System.Buffers.Text.Base64.EncodeToUtf8(
                    bytes.Slice(i, remaining <= 48 ? remaining : 48),
                    utf8[j..],
                    out int consumed,
                    out int written,
                    isFinalBlock: true);
                i += consumed;
                j += written;
                utf8[j++] = (byte)'\r';
                utf8[j++] = (byte)'\n';
            }

            utf8EndLabel.CopyTo(utf8[j..]);
            j += utf8EndLabel.Length;
            utf8[j++] = (byte)'\r';
            utf8[j++] = (byte)'\n';

            Debug.Assert(i == bytes.Length);
            Debug.Assert(j == utf8.Length);
        }

        public static int GetEncodedToUtf8Length(
            int inputLength,
            ReadOnlySpan<byte> utf8BeginLabel,
            ReadOnlySpan<byte> utf8EndLabel)
        {
            int base64Utf8Length = System.Buffers.Text.Base64.GetMaxEncodedToUtf8Length(inputLength);
            int crlfCount = (base64Utf8Length + 63) / 64;

            return utf8BeginLabel.Length + 2 +
                   base64Utf8Length + crlfCount * 2 +
                   utf8EndLabel.Length + 2;
        }

        public static bool TryDecodeFromUtf8(
            ReadOnlySpan<byte> utf8,
            ReadOnlySpan<byte> utf8BeginLabel,
            ReadOnlySpan<byte> utf8EndLabel,
            Span<byte> bytes,
            out int written)
        {
            Debug.Assert(!utf8BeginLabel.IsEmpty && utf8BeginLabel[0] == '-');
            Debug.Assert(!utf8EndLabel.IsEmpty && utf8EndLabel[0] == '-');

            ref sbyte decodingMap = ref s_decodingMap[0];

            int padding = 0;
            int buffer = 0;
            int filled = 0;
            int i = 0;
            int j = 0;

            for (; i < utf8.Length; i++)
            {
                int ch = utf8[i];
                if (ch == ' ' || ch >= '\t' && ch <= '\r')
                {
                    continue;
                }
                break;
            }

            if (!utf8[i..].StartsWith(utf8BeginLabel))
            {
                written = 0;
                return false;
            }
            i += utf8BeginLabel.Length;

            for (; i < utf8.Length; i++)
            {
                int ch = utf8[i];
                if (ch == ' ' || ch >= '\t' && ch <= '\r')
                {
                    continue;
                }
                int digit = Unsafe.Add(ref decodingMap, ch);
                if (digit < 0)
                {
                    break;
                }
                buffer = (buffer << 6) | digit;
                filled += 6;
                if (filled >= 8)
                {
                    if (j == bytes.Length)
                    {
                        written = 0;
                        return false;
                    }
                    bytes[j++] = (byte)((buffer >> (filled - 8)) & 255);
                    filled -= 8;
                }
            }

            for (; i < utf8.Length; i++)
            {
                int ch = utf8[i];
                if (ch == ' ' || ch >= '\t' && ch <= '\r')
                {
                    continue;
                }
                if (ch == '=')
                {
                    padding++;
                    filled += 6;
                    if (filled >= 8)
                    {
                        filled -= 8;
                    }
                    continue;
                }
                break;
            }

            if (!utf8[i..].StartsWith(utf8EndLabel))
            {
                written = 0;
                return false;
            }
            i += utf8EndLabel.Length;

            for (; i < utf8.Length; i++)
            {
                int ch = utf8[i];
                if (ch == ' ' || ch >= '\t' && ch <= '\r')
                {
                    continue;
                }
                break;
            }

            if (i < utf8.Length || filled > 0 || padding > 2)
            {
                written = 0;
                return false;
            }

            Debug.Assert(i == utf8.Length);
            written = j;
            return true;
        }

        private static readonly sbyte[] s_decodingMap =
        [
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
            -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        ];
    }
}
