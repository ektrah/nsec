using System;

namespace NSec.Tests
{
    internal static class Utilities
    {
        public static byte[] DecodeHex(this string s)
        {
            var result = new byte[s.Length / 2];
            for (var i = 0; i < result.Length; i++)
                result[i] = (byte)((ConvertHexDigit(s[2 * i + 0]) << 4) | ConvertHexDigit(s[2 * i + 1]));
            return result;
        }

        private static int ConvertHexDigit(char val)
        {
            if (val >= '0' && val <= '9')
                return (val - '0');
            else if (val >= 'a' && val <= 'f')
                return ((val - 'a') + 10);
            else if (val >= 'A' && val <= 'F')
                return ((val - 'A') + 10);
            else
                throw new Exception();
        }
    }
}
