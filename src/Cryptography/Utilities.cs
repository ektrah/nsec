using System;
using System.Runtime.CompilerServices;
using System.Buffers.Binary;

namespace NSec.Cryptography
{
    internal static class Utilities
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int CombineHash(
            int newKey,
            int currentKey)
        {
            return unchecked((currentKey * (int)0xA5555529) + newKey);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint FromBigEndian(
            uint value)
        {
            return BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(value) : value;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe bool Overlap(
            ReadOnlySpan<byte> first,
            ReadOnlySpan<byte> second)
        {
            return Overlap(first, second, out _);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe bool Overlap(
            ReadOnlySpan<byte> first,
            ReadOnlySpan<byte> second,
            out IntPtr byteOffset)
        {
            byteOffset = Unsafe.ByteOffset(ref first.DangerousGetPinnableReference(), ref second.DangerousGetPinnableReference());

            return (sizeof(IntPtr) == sizeof(int))
                ? second.Length != 0 && unchecked((uint)byteOffset < (uint)first.Length || (uint)byteOffset > (uint)-second.Length)
                : second.Length != 0 && unchecked((ulong)byteOffset < (ulong)first.Length || (ulong)byteOffset > (ulong)-second.Length);
        }
    }
}
