using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace NSec.Cryptography
{
    // RFC 5116
    [DebuggerDisplay("{GetDebuggerDisplay(),nq}")]
    [StructLayout(LayoutKind.Explicit)]
    public readonly struct Nonce : IEquatable<Nonce>
    {
        private const int maxSize = 24;

        public static readonly int MaxSize = maxSize;

        [FieldOffset(0)]
        private readonly byte _bytes;

        [FieldOffset(maxSize + 0)]
        private readonly byte _fixedFieldSize;

        [FieldOffset(maxSize + 1)]
        private readonly byte _counterFieldSize;

        [FieldOffset(maxSize + 2)]
        private readonly byte _reserved0;

        [FieldOffset(maxSize + 3)]
        private readonly byte _reserved1;

        public Nonce(
            int fixedFieldSize,
            int counterFieldSize)
            : this()
        {
            if (fixedFieldSize < 0 || fixedFieldSize > maxSize)
            {
                throw Error.ArgumentOutOfRange_NonceFixedCounterSize(nameof(fixedFieldSize), maxSize);
            }
            if (counterFieldSize < 0 || counterFieldSize > maxSize - fixedFieldSize)
            {
                throw Error.ArgumentOutOfRange_NonceCounterSize(nameof(counterFieldSize), maxSize);
            }

            _fixedFieldSize = (byte)fixedFieldSize;
            _counterFieldSize = (byte)counterFieldSize;
        }

        public Nonce(
            ReadOnlySpan<byte> fixedField,
            int counterFieldSize)
            : this()
        {
            if (fixedField.Length > maxSize)
            {
                throw Error.Argument_NonceFixedSize(nameof(fixedField), maxSize);
            }
            if (counterFieldSize < 0 || counterFieldSize > maxSize - fixedField.Length)
            {
                throw Error.ArgumentOutOfRange_NonceFixedCounterSize(nameof(counterFieldSize), maxSize);
            }

            _fixedFieldSize = (byte)fixedField.Length;
            _counterFieldSize = (byte)counterFieldSize;

            Unsafe.CopyBlockUnaligned(ref _bytes, ref Unsafe.AsRef(in fixedField.GetPinnableReference()), (uint)fixedField.Length);
        }

        public Nonce(
            ReadOnlySpan<byte> fixedField,
            ReadOnlySpan<byte> counterField)
            : this()
        {
            if (fixedField.Length > maxSize)
            {
                throw Error.Argument_NonceFixedSize(nameof(fixedField), maxSize);
            }
            if (counterField.Length > maxSize - fixedField.Length)
            {
                throw Error.Argument_NonceFixedCounterSize(nameof(counterField), maxSize);
            }

            _fixedFieldSize = (byte)fixedField.Length;
            _counterFieldSize = (byte)counterField.Length;

            Unsafe.CopyBlockUnaligned(ref _bytes, ref Unsafe.AsRef(in fixedField.GetPinnableReference()), (uint)fixedField.Length);
            Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref _bytes, fixedField.Length), ref Unsafe.AsRef(in counterField.GetPinnableReference()), (uint)counterField.Length);
        }

        public int CounterFieldSize => _counterFieldSize;

        public int FixedFieldSize => _fixedFieldSize;

        public int Size => _fixedFieldSize + _counterFieldSize;

        public static bool Equals(
            in Nonce left,
            in Nonce right)
        {
            if (Unsafe.SizeOf<Nonce>() != 6 * sizeof(uint) + 4 * sizeof(byte))
            {
                throw Error.InvalidOperation_InternalError();
            }
            if (right.Size != left.Size)
            {
                return false;
            }

            ref byte x = ref Unsafe.AsRef(in left._bytes);
            ref byte y = ref Unsafe.AsRef(in right._bytes);

            return Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 0 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 0 * sizeof(uint)))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 1 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 1 * sizeof(uint)))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 2 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 2 * sizeof(uint)))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 3 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 3 * sizeof(uint)))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 4 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 4 * sizeof(uint)))
                && Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 5 * sizeof(uint))) == Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 5 * sizeof(uint)));
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool Equals(
            object? objA,
            object? objB)
        {
            return object.Equals(objA, objB);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public static new bool ReferenceEquals(
            object? objA,
            object? objB)
        {
            return object.ReferenceEquals(objA, objB);
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
                    Debug.Assert(pos >= 0 && pos < maxSize);
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
            in Nonce other)
        {
            if (Unsafe.SizeOf<Nonce>() != 6 * sizeof(uint) + 4 * sizeof(byte))
            {
                throw Error.InvalidOperation_InternalError();
            }
            if (other.Size != nonce.Size)
            {
                throw Error.Argument_NonceXorSize(nameof(other));
            }

            Unsafe.AsRef(in nonce._fixedFieldSize) += nonce._counterFieldSize;
            Unsafe.AsRef(in nonce._counterFieldSize) = 0;

            ref byte x = ref Unsafe.AsRef(in nonce._bytes);
            ref byte y = ref Unsafe.AsRef(in other._bytes);

            Unsafe.WriteUnaligned(ref Unsafe.Add(ref x, 0 * sizeof(uint)), Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 0 * sizeof(uint))) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 0 * sizeof(uint))));
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref x, 1 * sizeof(uint)), Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 1 * sizeof(uint))) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 1 * sizeof(uint))));
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref x, 2 * sizeof(uint)), Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 2 * sizeof(uint))) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 2 * sizeof(uint))));
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref x, 3 * sizeof(uint)), Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 3 * sizeof(uint))) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 3 * sizeof(uint))));
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref x, 4 * sizeof(uint)), Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 4 * sizeof(uint))) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 4 * sizeof(uint))));
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref x, 5 * sizeof(uint)), Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 5 * sizeof(uint))) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref y, 5 * sizeof(uint))));
        }

        public static bool operator !=(
            Nonce left,
            Nonce right)
        {
            return !Equals(in left, in right);
        }

        public static Nonce operator ^(
            Nonce left,
            Nonce right)
        {
            Nonce result = left;
            Xor(ref result, in right);
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
                Unsafe.CopyBlockUnaligned(ref destination.GetPinnableReference(), ref Unsafe.AsRef(in _bytes), (uint)size);
            }
        }

        public bool Equals(
            Nonce other)
        {
            return Equals(in this, in other);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(
            object? obj)
        {
            return (obj is Nonce other) && Equals(in this, in other);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            if (Unsafe.SizeOf<Nonce>() != 6 * sizeof(uint) + 4 * sizeof(byte))
            {
                throw Error.InvalidOperation_InternalError();
            }

            ref byte x = ref Unsafe.AsRef(in _bytes);
            uint hashCode = unchecked((uint)Size);

            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 0 * sizeof(uint))));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 1 * sizeof(uint))));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 2 * sizeof(uint))));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 3 * sizeof(uint))));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 4 * sizeof(uint))));
            hashCode = unchecked(hashCode * 0xA5555529 + Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref x, 5 * sizeof(uint))));

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

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string? ToString()
        {
            return typeof(Nonce).ToString();
        }

        internal string GetDebuggerDisplay()
        {
            ref byte bytes = ref Unsafe.AsRef(in _bytes);
            int init = FixedFieldSize;
            int size = Size;
            StringBuilder sb = new StringBuilder(size * 2 + 4).Append('[');
            for (int i = 0; i < init; i++)
            {
                sb.Append(Unsafe.Add(ref bytes, i).ToString("X2", CultureInfo.InvariantCulture));
            }
            sb.Append(']').Append('[');
            for (int i = init; i < size; i++)
            {
                sb.Append(Unsafe.Add(ref bytes, i).ToString("X2", CultureInfo.InvariantCulture));
            }
            return sb.Append(']').ToString();
        }
    }
}
