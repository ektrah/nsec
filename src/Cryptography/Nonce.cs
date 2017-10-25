using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using NSec.Cryptography.Formatting;

namespace NSec.Cryptography
{
    // RFC 5116
    [StructLayout(LayoutKind.Explicit)]
    public readonly struct Nonce : IComparable<Nonce>, IEquatable<Nonce>
    {
        public const int MaxSize = 15;

        [FieldOffset(0)]
        private readonly byte _bytes;

        [FieldOffset(MaxSize)]
        private readonly byte _size;

        public Nonce(
            int fixedFieldSize,
            int counterFieldSize)
            : this()
        {
            if (fixedFieldSize < 0 || fixedFieldSize > MaxSize)
            {
                throw Error.ArgumentOutOfRange_NonceFixedCounterSize(nameof(fixedFieldSize));
            }
            if (counterFieldSize < 0 || counterFieldSize > MaxSize - fixedFieldSize)
            {
                throw Error.ArgumentOutOfRange_NonceCounterSize(nameof(counterFieldSize));
            }

            Debug.Assert(MaxSize >= 0x0 && MaxSize <= 0xF);

            _size = (byte)((fixedFieldSize << 4) | counterFieldSize);
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

            Unsafe.CopyBlockUnaligned(ref _bytes, ref fixedField.DangerousGetPinnableReference(), (uint)fixedField.Length);
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

            Unsafe.CopyBlockUnaligned(ref _bytes, ref fixedField.DangerousGetPinnableReference(), (uint)fixedField.Length);
            Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref _bytes, fixedField.Length), ref counterField.DangerousGetPinnableReference(), (uint)counterField.Length);
        }

        public int CounterFieldSize => _size & 0xF;

        public int FixedFieldSize => _size >> 4;

        public int Size => (_size >> 4) + (_size & 0xF);

        public static bool Equals(
            in Nonce left,
            in Nonce right)
        {
            Debug.Assert(Unsafe.SizeOf<Nonce>() == 16);

            ref byte first = ref Unsafe.AsRef(in left._bytes);
            ref byte second = ref Unsafe.AsRef(in right._bytes);

            return Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, 0x0)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, 0x0))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, 0x4)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, 0x4))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, 0x8)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, 0x8))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, 0xC)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, 0xC));
        }

        public static bool TryAdd(
            ref Nonce nonce,
            int value)
        {
            if (value < 0)
            {
                throw Error.ArgumentOutOfRange_NonceAddend(nameof(value));
            }

            ref byte source = ref Unsafe.AsRef(in nonce._bytes);
            uint carry = (uint)value;
            int end = nonce.FixedFieldSize;
            int pos = nonce.Size;

            while (carry != 0)
            {
                if (pos > end)
                {
                    pos--;
                    Debug.Assert(pos >= 0 && pos < MaxSize);
                    ref byte n = ref Unsafe.Add(ref source, pos);
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
            return !Equals(in left, in right);
        }

        public static Nonce operator ^(
            Nonce nonce,
            ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length != nonce.Size)
            {
                throw Error.Argument_NonceXorSize(nameof(bytes));
            }

            Nonce result = default(Nonce);
            Unsafe.AsRef(in result._size) = (byte)(bytes.Length << 4);

            ref byte destination = ref Unsafe.AsRef(in result._bytes);
            ref byte first = ref Unsafe.AsRef(in nonce._bytes);
            ref byte second = ref bytes.DangerousGetPinnableReference();

            int length = bytes.Length;
            int i = 0;

            while (length - i >= sizeof(int))
            {
                Debug.Assert(i >= 0 && i + 3 < MaxSize);
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, i),
                    Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, i)) ^
                    Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, i)));
                i += sizeof(int);
            }

            while (i != length)
            {
                Debug.Assert(i >= 0 && i < MaxSize);
                Unsafe.Add(ref destination, i) = unchecked((byte)(Unsafe.Add(ref first, i) ^ Unsafe.Add(ref second, i)));
                i++;
            }

            return result;
        }

        public static Nonce operator +(
            Nonce nonce,
            int value)
        {
            if (!TryAdd(ref nonce, value))
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
            return Equals(in left, in right);
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
            Debug.Assert(Unsafe.SizeOf<Nonce>() == 16);

            ref byte first = ref Unsafe.AsRef(in _bytes);
            ref byte second = ref Unsafe.AsRef(in other._bytes);
            uint x = _size;
            uint y = other._size;
            int i = 0;

            while (x == y && i < 16)
            {
                x = BitConverter.IsLittleEndian
                    ? BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, i)))
                    : Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, i));

                y = BitConverter.IsLittleEndian
                    ? BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, i)))
                    : Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, i));

                i += sizeof(uint);
            }

            return x.CompareTo(y);
        }

        public void CopyTo(
            Span<byte> destination)
        {
            int size = Size;
            if (destination.Length < size)
            {
                throw Error.Argument_DestinationTooShort(nameof(destination));
            }

            Unsafe.CopyBlockUnaligned(ref destination.DangerousGetPinnableReference(), ref Unsafe.AsRef(in _bytes), (uint)size);
        }

        public bool Equals(
            Nonce other)
        {
            return Equals(in this, in other);
        }

        public override bool Equals(
            object obj)
        {
            return (obj is Nonce other) && Equals(in this, in other);
        }

        public override int GetHashCode()
        {
            Debug.Assert(Unsafe.SizeOf<Nonce>() == 16);

            ref byte source = ref Unsafe.AsRef(in _bytes);
            uint hashCode = 0;

            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 0x0)));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 0x4)));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 0x8)));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 0xC)));

            return unchecked((int)hashCode);
        }

        public byte[] ToArray()
        {
            byte[] bytes = new byte[Size];
            Unsafe.CopyBlockUnaligned(ref bytes.AsSpan().DangerousGetPinnableReference(), ref Unsafe.AsRef(in _bytes), (uint)bytes.Length);
            return bytes;
        }

        public override string ToString()
        {
            Span<byte> bytes = stackalloc byte[Size];
            Unsafe.CopyBlockUnaligned(ref bytes.DangerousGetPinnableReference(), ref Unsafe.AsRef(in _bytes), (uint)bytes.Length);
            return string.Concat("[", Base16.Encode(bytes).Insert(2 * FixedFieldSize, "]["), "]");
        }
    }
}
