using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using NSec.Cryptography.Formatting;

namespace NSec.Cryptography
{
    // RFC 5116
    [StructLayout(LayoutKind.Explicit)]
    public struct Nonce : IComparable<Nonce>, IEquatable<Nonce>
    {
        public const int MaxSize = 15;

        [FieldOffset(0)]
        private byte _value0;

        [FieldOffset(MaxSize)]
        private byte _size;

        public Nonce(
            int counterFieldSize)
            : this()
        {
            if (counterFieldSize < 0 || counterFieldSize > MaxSize)
            {
                throw Error.ArgumentOutOfRange_NonceCounterSize(nameof(counterFieldSize));
            }

            Debug.Assert(MaxSize >= 0x0 && MaxSize <= 0xF);

            _size = (byte)counterFieldSize;
        }

        public Nonce(
            ReadOnlySpan<byte> fixedField,
            int counterFieldSize)
            : this()
        {
            if (fixedField.Length > MaxSize)
            {
                throw Error.Argument_NonceFixedSize(nameof(fixedField));
            }
            if (counterFieldSize < 0 || counterFieldSize > MaxSize - fixedField.Length)
            {
                throw Error.ArgumentOutOfRange_NonceFixedCounterSize(nameof(counterFieldSize));
            }

            Debug.Assert(MaxSize >= 0x0 && MaxSize <= 0xF);

            _size = (byte)((fixedField.Length << 4) | counterFieldSize);

            Unsafe.CopyBlockUnaligned(ref _value0, ref fixedField.DangerousGetPinnableReference(), (uint)fixedField.Length);
        }

        public Nonce(
            ReadOnlySpan<byte> fixedField,
            ReadOnlySpan<byte> counterField)
            : this()
        {
            if (fixedField.Length > MaxSize)
            {
                throw Error.Argument_NonceFixedSize(nameof(fixedField));
            }
            if (counterField.Length > MaxSize - fixedField.Length)
            {
                throw Error.Argument_NonceFixedCounterSize(nameof(counterField));
            }

            Debug.Assert(MaxSize >= 0x0 && MaxSize <= 0xF);

            _size = (byte)((fixedField.Length << 4) | counterField.Length);

            Unsafe.CopyBlockUnaligned(ref _value0, ref fixedField.DangerousGetPinnableReference(), (uint)fixedField.Length);
            Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref _value0, fixedField.Length), ref counterField.DangerousGetPinnableReference(), (uint)counterField.Length);
        }

        public int CounterFieldSize => _size & 0xF;

        public int FixedFieldSize => _size >> 4;

        public int Size => (_size >> 4) + (_size & 0xF);

        public static bool TryAdd(
            ref Nonce nonce,
            int addend)
        {
            if (addend < 0)
            {
                throw Error.ArgumentOutOfRange_NonceAddend(nameof(addend));
            }

            uint carry = (uint)addend;
            int end = nonce.FixedFieldSize;
            int pos = nonce.Size;

            while (carry != 0)
            {
                if (pos > end)
                {
                    pos--;
                    Debug.Assert(pos >= 0 && pos < MaxSize);
                    ref byte n = ref Unsafe.Add(ref nonce._value0, pos);
                    carry += n;
                    n = unchecked((byte)carry);
                    carry >>= 8;
                }
                else
                {
                    nonce = default;
                    return false;
                }
            }

            return true;
        }

        public static bool TryIncrement(
            ref Nonce nonce)
        {
            return TryAdd(ref nonce, 1);
        }

        public static bool operator !=(
            Nonce left,
            Nonce right)
        {
            return !left.Equals(right);
        }

        public static Nonce operator ^(
            Nonce nonce,
            ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length != nonce.Size)
            {
                throw Error.Argument_NonceXorSize(nameof(bytes));
            }

            nonce._size = (byte)(bytes.Length << 4);

            ref byte first = ref nonce._value0;
            ref byte second = ref bytes.DangerousGetPinnableReference();

            int length = bytes.Length;
            int i = 0;

            while (length - i >= sizeof(int))
            {
                ref byte x = ref Unsafe.Add(ref first, i);
                ref byte y = ref Unsafe.Add(ref second, i);

                Unsafe.WriteUnaligned(ref x, Unsafe.ReadUnaligned<int>(ref x) ^ Unsafe.ReadUnaligned<int>(ref y));
                i += sizeof(int);
            }

            while (i != length)
            {
                Debug.Assert(i >= 0 && i < MaxSize);
                Unsafe.Add(ref first, i) ^= Unsafe.Add(ref second, i);
                i++;
            }

            return nonce;
        }

        public static Nonce operator +(
            Nonce nonce,
            int addend)
        {
            if (!TryAdd(ref nonce, addend))
            {
                throw Error.Overflow_NonceCounter();
            }
            return nonce;
        }

        public static Nonce operator ++(
            Nonce nonce)
        {
            if (!TryAdd(ref nonce, 1))
            {
                throw Error.Overflow_NonceCounter();
            }
            return nonce;
        }

        public static bool operator <(
            Nonce left,
            Nonce right)
        {
            return left.CompareTo(right) < 0;
        }

        public static bool operator <=(
            Nonce left,
            Nonce right)
        {
            return left.CompareTo(right) <= 0;
        }

        public static bool operator ==(
            Nonce left,
            Nonce right)
        {
            return left.Equals(right);
        }

        public static bool operator >(
            Nonce left,
            Nonce right)
        {
            return left.CompareTo(right) > 0;
        }

        public static bool operator >=(
            Nonce left,
            Nonce right)
        {
            return left.CompareTo(right) >= 0;
        }

        public int CompareTo(
            Nonce other)
        {
            Debug.Assert(Unsafe.SizeOf<Nonce>() % sizeof(uint) == 0);

            uint x = _size;
            uint y = other._size;

            for (int i = 0; x == y && i < Unsafe.SizeOf<Nonce>(); i += sizeof(uint))
            {
                x = Utilities.FromBigEndian(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref _value0, i)));
                y = Utilities.FromBigEndian(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref other._value0, i)));
            }

            return x.CompareTo(y);
        }

        public int CopyTo(
            Span<byte> destination)
        {
            int size = Size;
            if (destination.Length < size)
            {
                throw Error.Argument_DestinationTooShort(nameof(destination));
            }

            Unsafe.CopyBlockUnaligned(ref destination.DangerousGetPinnableReference(), ref _value0, (uint)size);
            return size;
        }

        public bool Equals(
            Nonce other)
        {
            Debug.Assert(Unsafe.SizeOf<Nonce>() == 16);

            return Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref _value0, 0x0)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref other._value0, 0x0))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref _value0, 0x4)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref other._value0, 0x4))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref _value0, 0x8)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref other._value0, 0x8))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref _value0, 0xC)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref other._value0, 0xC));
        }

        public override bool Equals(
            object obj)
        {
            return (obj is Nonce other) && Equals(other);
        }

        public override int GetHashCode()
        {
            Debug.Assert(Unsafe.SizeOf<Nonce>() == 16);

            int hashCode = 0;
            hashCode = Utilities.CombineHash(Unsafe.ReadUnaligned<int>(ref Unsafe.Add(ref _value0, 0x0)), hashCode);
            hashCode = Utilities.CombineHash(Unsafe.ReadUnaligned<int>(ref Unsafe.Add(ref _value0, 0x4)), hashCode);
            hashCode = Utilities.CombineHash(Unsafe.ReadUnaligned<int>(ref Unsafe.Add(ref _value0, 0x8)), hashCode);
            hashCode = Utilities.CombineHash(Unsafe.ReadUnaligned<int>(ref Unsafe.Add(ref _value0, 0xC)), hashCode);
            return hashCode;
        }

        public byte[] ToArray()
        {
            byte[] bytes = new byte[Size];
            Unsafe.CopyBlockUnaligned(ref bytes.AsSpan().DangerousGetPinnableReference(), ref _value0, (uint)bytes.Length);
            return bytes;
        }

        public override string ToString()
        {
            Span<byte> bytes = stackalloc byte[Size];
            Unsafe.CopyBlockUnaligned(ref bytes.DangerousGetPinnableReference(), ref _value0, (uint)bytes.Length);
            return string.Concat("[", Base16.Encode(bytes).Insert(2 * FixedFieldSize, "]["), "]");
        }
    }
}
