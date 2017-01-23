using System;

namespace NSec.Cryptography
{
    internal struct Oid
    {
        private readonly byte[] _bytes;

        public Oid(
            int first,
            int second,
            params int[] rest)
        {
            int length = GetLength(first * 40 + second);
            for (int i = 0; i < rest.Length; i++)
                length += GetLength(rest[i]);
            byte[] bytes = new byte[length];
            int pos = Encode(first * 40 + second, bytes, 0);
            for (int i = 0; i < rest.Length; i++)
                pos += Encode(rest[i], bytes, pos);
            _bytes = bytes;
        }

        public ReadOnlySpan<byte> Bytes => _bytes != null ? _bytes : ReadOnlySpan<byte>.Empty;

        private static int Encode(
            int value,
            byte[] buffer,
            int pos)
        {
            int length = 0;
            for (int v = value; v != 0; v >>= 7)
                length++;
            for (int i = 0; i < length - 1; i++)
                buffer[pos + i] = (byte)((value >> (7 * (length - i - 1))) & 0x7F | 0x80);
            buffer[pos + length - 1] = (byte)(value & 0x7F);
            return length;
        }

        private static int GetLength(int value)
        {
            int length = 0;
            for (int v = value; v > 0; v >>= 7)
                length++;
            return length;
        }
    }
}
