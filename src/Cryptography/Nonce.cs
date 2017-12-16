using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

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

            Unsafe.CopyBlockUnaligned(ref _bytes, ref Unsafe.AsRef(in MemoryMarshal.GetReference(fixedField)), (uint)fixedField.Length);
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

            Unsafe.CopyBlockUnaligned(ref _bytes, ref Unsafe.AsRef(in MemoryMarshal.GetReference(fixedField)), (uint)fixedField.Length);
            Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref _bytes, fixedField.Length), ref Unsafe.AsRef(in MemoryMarshal.GetReference(counterField)), (uint)counterField.Length);
        }

        public int CounterFieldSize => _size & 0xF;

        public int FixedFieldSize => _size >> 4;

        public int Size => (_size >> 4) + (_size & 0xF);

        public static int Compare(
            in Nonce left,
            in Nonce right)
        {
            Debug.Assert(Unsafe.SizeOf<Nonce>() == 16);

            ref readonly byte first = ref left._bytes;
            ref readonly byte second = ref right._bytes;
            uint x = left._size;
            uint y = right._size;
            int i = 0;

            while (x == y && i < 16)
            {
                x = BitConverter.IsLittleEndian
                    ? BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in first), i)))
                    : Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in first), i));

                y = BitConverter.IsLittleEndian
                    ? BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in second), i)))
                    : Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(second), i));

                i += sizeof(uint);
            }

            return x.CompareTo(y);
        }

        public static bool Equals(
            in Nonce left,
            in Nonce right)
        {
            Debug.Assert(Unsafe.SizeOf<Nonce>() == 16);

            ref readonly byte first = ref left._bytes;
            ref readonly byte second = ref right._bytes;

            return Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in first), 0x0)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in second), 0x0))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in first), 0x4)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in second), 0x4))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in first), 0x8)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in second), 0x8))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in first), 0xC)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in second), 0xC));
        }

        public static bool TryAdd(
            ref Nonce nonce,
            int value)
        {
            if (value < 0)
            {
                throw Error.ArgumentOutOfRange_NonceAddend(nameof(value));
            }

            ref byte bytes = ref Unsafe.AsRef(in nonce._bytes);
            uint carry = (uint)value;
            int end = nonce.FixedFieldSize;
            int pos = nonce.Size;

            while (carry != 0)
            {
                if (pos > end)
                {
                    pos--;
                    Debug.Assert(pos >= 0 && pos < MaxSize);
                    ref byte n = ref Unsafe.Add(ref bytes, pos);
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

        public static void Xor(
            ref Nonce nonce,
            ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length != nonce.Size)
            {
                throw Error.Argument_NonceXorSize(nameof(bytes));
            }

            Unsafe.AsRef(in nonce._size) = (byte)((bytes.Length << 4) | 0);

            ref byte result = ref Unsafe.AsRef(in nonce._bytes);
            ref readonly byte first_ = ref nonce._bytes;
            ref readonly byte second_ = ref MemoryMarshal.GetReference(bytes);
            int length = bytes.Length;
            int i = 0;

            while (length - i >= sizeof(uint))
            {
                Debug.Assert(i >= 0 && i + 3 < MaxSize);
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref result, i),
                    Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in first_), i)) ^
                    Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in second_), i)));
                i += sizeof(uint);
            }

            while (i < length)
            {
                Debug.Assert(i >= 0 && i < MaxSize);
                Unsafe.Add(ref result, i) = (byte)(
                    Unsafe.Add(ref Unsafe.AsRef(in first_), i) ^
                    Unsafe.Add(ref Unsafe.AsRef(in second_), i));
                i++;
            }
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
            Nonce result = nonce;
            Xor(ref result, bytes);
            return result;
        }

        public static Nonce operator +(
            Nonce nonce,
            int value)
        {
            Nonce result = nonce;
            if (!TryAdd(ref result, value))
            {
                throw Error.Overflow_NonceCounter();
            }
            return result;
        }

        public static Nonce operator ++(
            Nonce nonce)
        {
            Nonce result = nonce;
            if (!TryAdd(ref result, 1))
            {
                throw Error.Overflow_NonceCounter();
            }
            return result;
        }

        public static bool operator <(
            Nonce left,
            Nonce right)
        {
            return Compare(in left, in right) < 0;
        }

        public static bool operator <=(
            Nonce left,
            Nonce right)
        {
            return Compare(in left, in right) <= 0;
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
            return Compare(in left, in right) > 0;
        }

        public static bool operator >=(
            Nonce left,
            Nonce right)
        {
            return Compare(in left, in right) >= 0;
        }

        public int CompareTo(
            Nonce other)
        {
            return Compare(in this, in other);
        }

        public void CopyTo(
            Span<byte> destination)
        {
            int size = Size;
            if (destination.Length < size)
            {
                throw Error.Argument_DestinationTooShort(nameof(destination));
            }
            if (size > 0)
            {
                Unsafe.CopyBlockUnaligned(ref MemoryMarshal.GetReference(destination), ref Unsafe.AsRef(in _bytes), (uint)size);
            }
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

            ref readonly byte source = ref _bytes;
            uint hashCode = 0;

            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in source), 0x0)));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in source), 0x4)));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in source), 0x8)));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref Unsafe.AsRef(in source), 0xC)));

            return unchecked((int)hashCode);
        }

        public byte[] ToArray()
        {
            int size = Size;
            byte[] bytes = new byte[size];
            if (size > 0)
            {
                Unsafe.CopyBlockUnaligned(ref bytes[0], ref Unsafe.AsRef(in _bytes), (uint)size);
            }
            return bytes;
        }

        public override string ToString()
        {
            ref readonly byte source = ref _bytes;
            int init = FixedFieldSize;
            int size = Size;
            StringBuilder sb = new StringBuilder(size * 2 + 4).Append('[');
            for (int i = 0; i < init; i++)
            {
                sb.Append(Unsafe.Add(ref Unsafe.AsRef(in source), i).ToString("X2"));
            }
            sb.Append(']').Append('[');
            for (int i = init; i < size; i++)
            {
                sb.Append(Unsafe.Add(ref Unsafe.AsRef(in source), i).ToString("X2"));
            }
            return sb.Append(']').ToString();
        }
    }
}
