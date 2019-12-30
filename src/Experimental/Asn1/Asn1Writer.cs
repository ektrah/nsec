using System;
using System.Runtime.CompilerServices;
using NSec.Cryptography;

namespace NSec.Experimental.Asn1
{
    // ITU-T X.690 5.0 DER
    internal ref struct Asn1Writer
    {
        internal const int MaxDepth = 6;

#pragma warning disable 0414
        private int _stack0;
        private int _stack1;
        private int _stack2;
        private int _stack3;
        private int _stack4;
        private int _stack5;
#pragma warning restore 0414

        private Span<byte> _buffer;
        private int _depth;
        private int _pos;

        public Asn1Writer(
            Span<byte> buffer)
        {
            _stack0 = default;
            _stack1 = default;
            _stack2 = default;
            _stack3 = default;
            _stack4 = default;
            _stack5 = default;

            _buffer = buffer;
            _depth = 0;
            _pos = buffer.Length;
        }

        public readonly ReadOnlySpan<byte> Bytes => _buffer.Slice(_pos);

        public void BeginSequence()
        {
            if (_depth == 0)
            {
                throw Error.InvalidOperation_InternalError(); // underflow
            }

            _depth--;
            WriteLength(Unsafe.Add(ref _stack0, _depth) - _pos);
            WriteByte(0x30);
        }

        public void BitString(
            ReadOnlySpan<byte> bits)
        {
            WriteBytes(bits);
            WriteByte(0);
            WriteLength(1 + bits.Length);
            WriteByte(0x03);
        }

        public void Bool(
            bool value)
        {
            WriteByte((byte)(value ? 0xFF : 0x00));
            WriteLength(1);
            WriteByte(0x01);
        }

        public void End()
        {
            if (_depth == MaxDepth)
            {
                throw Error.InvalidOperation_InternalError(); // overflow
            }

            Unsafe.Add(ref _stack0, _depth) = _pos;
            _depth++;
        }

        public void Integer(
            int value)
        {
            int end = _pos;
            WriteByte(unchecked((byte)value));
            while ((value & ~0x7F) != 0 && (value & ~0x7F) != ~0x7F)
            {
                value >>= 8;
                WriteByte(unchecked((byte)value));
            }
            WriteLength(end - _pos);
            WriteByte(0x02);
        }

        public void Integer(
            long value)
        {
            int end = _pos;
            WriteByte(unchecked((byte)value));
            while ((value & ~0x7F) != 0 && (value & ~0x7F) != ~0x7F)
            {
                value >>= 8;
                WriteByte(unchecked((byte)value));
            }
            WriteLength(end - _pos);
            WriteByte(0x02);
        }

        public void Null()
        {
            WriteLength(0);
            WriteByte(0x05);
        }

        public void ObjectIdentifier(
            ReadOnlySpan<byte> oid)
        {
            WriteBytes(oid);
            WriteLength(oid.Length);
            WriteByte(0x06);
        }

        public void OctetString(
            ReadOnlySpan<byte> octets)
        {
            WriteBytes(octets);
            WriteLength(octets.Length);
            WriteByte(0x04);
        }

        private void WriteByte(
            byte value)
        {
            if (_pos == 0)
            {
                throw Error.InvalidOperation_InternalError(); // not enough space
            }

            _pos--;
            _buffer[_pos] = value;
        }

        private void WriteBytes(
            ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length > _pos)
            {
                throw Error.InvalidOperation_InternalError(); // not enough space
            }

            _pos -= bytes.Length;
            bytes.CopyTo(_buffer.Slice(_pos));
        }

        private void WriteLength(
            int length)
        {
            if (length < 0x80)
            {
                WriteByte((byte)length);
            }
            else
            {
                int end = _pos;
                WriteByte(unchecked((byte)length));
                while ((length & ~0xFF) != 0)
                {
                    length >>= 8;
                    WriteByte(unchecked((byte)length));
                }
                WriteByte((byte)(0x80 + (end - _pos)));
            }
        }
    }
}
