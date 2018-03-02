using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace NSec.Cryptography
{
    // RFC 5116
    [StructLayout(LayoutKind.Explicit)]
    public readonly struct Nonce : IEquatable<Nonce>
    {
        public const int MaxSize = 24;

        [FieldOffset(0)]
        private readonly byte _bytes;

        [FieldOffset(MaxSize + 0)]
        private readonly byte _fixedFieldSize;

        [FieldOffset(MaxSize + 1)]
        private readonly byte _counterFieldSize;

        [FieldOffset(MaxSize + 2)]
        private readonly byte _reserved0;

        [FieldOffset(MaxSize + 3)]
        private readonly byte _reserved1;

        public Nonce(
            int fixedFieldSize,
            int counterFieldSize)
            : this()
        {
            if (fixedFieldSize < 0 || fixedFieldSize > MaxSize)
            {
                throw Error.ArgumentOutOfRange_NonceFixedCounterSize(nameof(fixedFieldSize), MaxSize.ToString());
            }
            if (counterFieldSize < 0 || counterFieldSize > MaxSize - fixedFieldSize)
            {
                throw Error.ArgumentOutOfRange_NonceCounterSize(nameof(counterFieldSize), MaxSize.ToString());
            }

            _fixedFieldSize = (byte)fixedFieldSize;
            _counterFieldSize = (byte)counterFieldSize;
        }

        public Nonce(
            ReadOnlySpan<byte> fixedField,
            int counterFieldSize)
            : this()
        {
            if (fixedField.Length > MaxSize)
            {
                throw Error.Argument_NonceFixedSize(nameof(fixedField), MaxSize.ToString());
            }
            if (counterFieldSize < 0 || counterFieldSize > MaxSize - fixedField.Length)
            {
                throw Error.ArgumentOutOfRange_NonceFixedCounterSize(nameof(counterFieldSize), MaxSize.ToString());
            }

            _fixedFieldSize = (byte)fixedField.Length;
            _counterFieldSize = (byte)counterFieldSize;

            Unsafe.CopyBlockUnaligned(ref _bytes, ref Unsafe.AsRef(in MemoryMarshal.GetReference(fixedField)), (uint)fixedField.Length);
        }

        public Nonce(
            ReadOnlySpan<byte> fixedField,
            ReadOnlySpan<byte> counterField)
            : this()
        {
            if (fixedField.Length > MaxSize)
            {
                throw Error.Argument_NonceFixedSize(nameof(fixedField), MaxSize.ToString());
            }
            if (counterField.Length > MaxSize - fixedField.Length)
            {
                throw Error.Argument_NonceFixedCounterSize(nameof(counterField), MaxSize.ToString());
            }

            _fixedFieldSize = (byte)fixedField.Length;
            _counterFieldSize = (byte)counterField.Length;

            Unsafe.CopyBlockUnaligned(ref _bytes, ref Unsafe.AsRef(in MemoryMarshal.GetReference(fixedField)), (uint)fixedField.Length);
            Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref _bytes, fixedField.Length), ref Unsafe.AsRef(in MemoryMarshal.GetReference(counterField)), (uint)counterField.Length);
        }

        public int CounterFieldSize => _counterFieldSize;

        public int FixedFieldSize => _fixedFieldSize;

        public int Size => _fixedFieldSize + _counterFieldSize;

        public static bool Equals(
            in Nonce left,
            in Nonce right)
        {
            if (Unsafe.SizeOf<Nonce>() != 28)
            {
                throw Error.Cryptographic_InternalError();
            }

            ref byte first = ref Unsafe.AsRef(in left._bytes);
            ref byte second = ref Unsafe.AsRef(in right._bytes);

            return Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, 0)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, 0))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, 4)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, 4))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, 8)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, 8))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, 12)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, 12))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, 16)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, 16))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, 20)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, 20))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, 24)) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, 24));
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

            Unsafe.AsRef(in nonce._fixedFieldSize) = (byte)bytes.Length;
            Unsafe.AsRef(in nonce._counterFieldSize) = 0;

            ref byte first = ref Unsafe.AsRef(in nonce._bytes);
            ref byte second = ref Unsafe.AsRef(in MemoryMarshal.GetReference(bytes));
            int length = bytes.Length;
            int i = 0;

            while (length - i >= sizeof(uint))
            {
                Debug.Assert(i >= 0 && i + 3 < MaxSize);
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref first, i),
                    Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref first, i)) ^
                    Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref second, i)));
                i += sizeof(uint);
            }

            while (i < length)
            {
                Debug.Assert(i >= 0 && i < MaxSize);
                Unsafe.Add(ref first, i) ^= Unsafe.Add(ref second, i);
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

        public static bool operator ==(
            Nonce left,
            Nonce right)
        {
            return Equals(in left, in right);
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
            if (Unsafe.SizeOf<Nonce>() != 28)
            {
                throw Error.Cryptographic_InternalError();
            }

            ref byte bytes = ref Unsafe.AsRef(in _bytes);
            uint hashCode = 0;

            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref bytes, 0)));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref bytes, 4)));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref bytes, 8)));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref bytes, 12)));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref bytes, 16)));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref bytes, 20)));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref bytes, 24)));

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
            ref byte bytes = ref Unsafe.AsRef(in _bytes);
            int init = FixedFieldSize;
            int size = Size;
            StringBuilder sb = new StringBuilder(size * 2 + 4).Append('[');
            for (int i = 0; i < init; i++)
            {
                sb.Append(Unsafe.Add(ref bytes, i).ToString("X2"));
            }
            sb.Append(']').Append('[');
            for (int i = init; i < size; i++)
            {
                sb.Append(Unsafe.Add(ref bytes, i).ToString("X2"));
            }
            return sb.Append(']').ToString();
        }
    }
}
