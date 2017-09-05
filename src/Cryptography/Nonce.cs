using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using NSec.Cryptography.Formatting;

namespace NSec.Cryptography
{
    // RFC 5116
    public struct Nonce : IComparable<Nonce>, IEquatable<Nonce>
    {
        public const int MaxSize = 15;

#pragma warning disable 0169
        private byte _value0;
        private byte _value1;
        private byte _value2;
        private byte _value3;
        private byte _value4;
        private byte _value5;
        private byte _value6;
        private byte _value7;
        private byte _value8;
        private byte _value9;
        private byte _value10;
        private byte _value11;
        private byte _value12;
        private byte _value13;
        private byte _value14;
#pragma warning restore 0169

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

            int offset = nonce.Size - 1;
            int size = nonce.CounterFieldSize;
            int carry = addend;

            for (int i = 0; i < size; i++)
            {
                Debug.Assert(offset - i >= 0 && offset - i < MaxSize);
                ref byte n = ref Unsafe.Add(ref nonce._value0, offset - i);
                n = unchecked((byte)(carry += n));
                carry >>= 8;
            }

            if (carry != 0)
            {
                nonce = default;
                return false;
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

            for (int i = 0; i < bytes.Length; i++)
            {
                Debug.Assert(i >= 0 && i < MaxSize);
                Unsafe.Add(ref nonce._value0, i) ^= bytes[i];
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
            int gt = ((other._size - _size) >> 31) & 1;
            int eq = (((other._size ^ _size) - 1) >> 31) & 1;

            for (int i = 0; i < MaxSize; i++)
            {
                int x = Unsafe.Add(ref _value0, i);
                int y = Unsafe.Add(ref other._value0, i);
                gt |= ((y - x) >> 31) & eq;
                eq &= ((y ^ x) - 1) >> 31;
            }

            return gt + gt + eq - 1;
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
            int eq = other._size ^ _size;

            for (int i = 0; i < MaxSize; i++)
            {
                int x = Unsafe.Add(ref _value0, i);
                int y = Unsafe.Add(ref other._value0, i);
                eq |= y ^ x;
            }

            return (((eq - 1) >> 31) & 1) - 1 == 0;
        }

        public override bool Equals(
            object obj)
        {
            return (obj is Nonce other) && Equals(other);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                // FNV-1a
                const uint FNV32Prime = 0x01000193U;
                const uint FNV32Basis = 0x811C9DC5U;

                uint hashCode = FNV32Basis;

                hashCode = (hashCode ^ _size) * FNV32Prime;

                for (int i = 0; i < MaxSize; i++)
                {
                    hashCode = (hashCode ^ Unsafe.Add(ref _value0, i)) * FNV32Prime;
                }

                return (int)hashCode;
            }
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
