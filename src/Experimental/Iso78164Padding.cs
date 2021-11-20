using System;

namespace NSec.Experimental
{
    public static class Iso78164Padding
    {
        public static int GetPaddedLength(
            int unpaddedLength,
            int blockSize)
        {
            if (blockSize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(blockSize));
            }

            int padLength = blockSize - unpaddedLength % blockSize;

            if (padLength > int.MaxValue - unpaddedLength)
            {
                throw new ArgumentOutOfRangeException(nameof(blockSize));
            }

            return unpaddedLength + padLength;
        }

        public static byte[] Pad(
            ReadOnlySpan<byte> unpadded,
            int blockSize)
        {
            byte[] padded = new byte[GetPaddedLength(unpadded.Length, blockSize)];
            unpadded.CopyTo(padded);
            padded[unpadded.Length] = 0x80;
            return padded;
        }

        public static void Pad(
            ReadOnlySpan<byte> unpadded,
            int blockSize,
            Span<byte> padded)
        {
            if (padded.Length != GetPaddedLength(unpadded.Length, blockSize))
            {
                throw new ArgumentException();
            }

            if (padded.Overlaps(unpadded, out int offset))
            {
                if (offset != 0)
                {
                    throw new ArgumentException();
                }
            }
            else
            {
                unpadded.CopyTo(padded);
            }

            padded[unpadded.Length] = 0x80;
            padded[(unpadded.Length + 1)..].Clear();
        }

        public static byte[]? Unpad(
            ReadOnlySpan<byte> padded,
            int blockSize)
        {
            return Unpad(padded, blockSize, out ReadOnlySpan<byte> unpadded) ? unpadded.ToArray() : null;
        }

        public static bool Unpad(
            ReadOnlySpan<byte> padded,
            int blockSize,
            out ReadOnlySpan<byte> result)
        {
            if (blockSize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(blockSize));
            }

            int lastBlockStart = padded.Length - blockSize;

            if (lastBlockStart >= 0 && padded.Length % blockSize == 0)
            {
                for (int i = padded.Length - 1; i >= lastBlockStart; i--)
                {
                    if (padded[i] == 0)
                    {
                        continue;
                    }
                    else if (padded[i] == 0x80)
                    {
                        result = padded[..i];
                        return true;
                    }
                    else
                    {
                        break;
                    }
                }
            }

            result = default;
            return false;
        }
    }
}
