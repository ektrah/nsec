using System;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography
{
    internal static class Utilities
    {
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
                ? !first.IsEmpty && !second.IsEmpty && unchecked((uint)byteOffset < (uint)first.Length || (uint)byteOffset > (uint)-second.Length)
                : !first.IsEmpty && !second.IsEmpty && unchecked((ulong)byteOffset < (ulong)first.Length || (ulong)byteOffset > (ulong)-second.Length);
        }
    }
}
