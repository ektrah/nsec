using System;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography
{
    internal static class Utilities
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe bool Overlap<T>(
            ReadOnlySpan<T> left,
            ReadOnlySpan<T> right)
        {
            ref T x1 = ref left.DangerousGetPinnableReference();
            ref T y1 = ref right.DangerousGetPinnableReference();

            ref T x2 = ref Unsafe.Add(ref x1, left.Length);
            ref T y2 = ref Unsafe.Add(ref y1, right.Length);

            IntPtr diff1 = Unsafe.ByteOffset(ref x1, ref y2);
            IntPtr diff2 = Unsafe.ByteOffset(ref y1, ref x2);

            return (sizeof(IntPtr) == sizeof(int) ? (int)diff1 > 0 : (long)diff1 > 0)
                && (sizeof(IntPtr) == sizeof(int) ? (int)diff2 > 0 : (long)diff2 > 0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static T Read<T>(
            this ReadOnlySpan<byte> span)
            where T : struct
        {
            if (span.Length < Unsafe.SizeOf<T>())
            {
                ThrowArgumentException();
            }

            return Unsafe.ReadUnaligned<T>(ref span.DangerousGetPinnableReference());
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ReadBigEndian(
            this ReadOnlySpan<byte> span)
        {
            return BitConverter.IsLittleEndian ? Reverse(span.Read<uint>()) : span.Read<uint>();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ReadLittleEndian(
            this ReadOnlySpan<byte> span)
        {
            return BitConverter.IsLittleEndian ? span.Read<uint>() : Reverse(span.Read<uint>());
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ToBigEndian(
            uint value)
        {
            return BitConverter.IsLittleEndian ? Reverse(value) : value;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Write<T>(
            this Span<byte> span,
            T value)
            where T : struct
        {
            if (span.Length < Unsafe.SizeOf<T>())
            {
                ThrowArgumentException();
            }

            Unsafe.WriteUnaligned(ref span.DangerousGetPinnableReference(), value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteBigEndian(
            this Span<byte> span,
            uint value)
        {
            span.Write(BitConverter.IsLittleEndian ? Reverse(value) : value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteLittleEndian(
            this Span<byte> span,
            uint value)
        {
            span.Write(BitConverter.IsLittleEndian ? value : Reverse(value));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Reverse(
            uint value)
        {
            return unchecked(
                (value << 24) |
                ((value & 0xFF00) << 8) |
                ((value & 0xFF0000) >> 8) |
                (value >> 24));
        }

        private static void ThrowArgumentException()
        {
            throw new ArgumentException();
        }
    }
}
