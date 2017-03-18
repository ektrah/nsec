using System;

namespace NSec.Cryptography.Formatting
{
    // ITU-T X.690 5.0 DER
    internal struct Asn1Writer
    {
        private Span<byte> _buffer;
        private int _depth;
        private int _pos;
        private int[] _stack;

        public Asn1Writer(
            ref Span<byte> buffer, 
            int maxDepth = 8)
        {
            _buffer = buffer;
            _depth = 0;
            _pos = buffer.Length;
            _stack = new int[maxDepth];
        }

        public ReadOnlySpan<byte> Bytes => _buffer.Slice(_pos);

        public void BeginSequence()
        {
            _depth--;
            WriteLength(_stack[_depth] - _pos);
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
            unchecked
            {
                WriteByte((byte)(value ? -1 : 0));
            }
            WriteLength(1);
            WriteByte(0x01);
        }

        public void End()
        {
            _stack[_depth] = _pos;
            _depth++;
        }

        public void Integer(
            int value)
        {
            int end = _pos;
            unchecked
            {
                WriteByte((byte)value);
                while ((value & ~0x7F) != 0 && (value & ~0x7F) != ~0x7F)
                {
                    value >>= 8;
                    WriteByte((byte)value);
                }
            }
            WriteLength(end - _pos);
            WriteByte(0x02);
        }

        public void Integer(
            long value)
        {
            int end = _pos;
            unchecked
            {
                WriteByte((byte)value);
                while ((value & ~0x7F) != 0 && (value & ~0x7F) != ~0x7F)
                {
                    value >>= 8;
                    WriteByte((byte)value);
                }
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
                throw new ArgumentException(); // not enough space

            _pos--;
            _buffer[_pos] = value;
        }

        private void WriteBytes(
            ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length > _pos)
                throw new ArgumentException(); // not enough space

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
                unchecked
                {
                    WriteByte((byte)length);
                    while ((length & ~0xFF) != 0)
                    {
                        length >>= 8;
                        WriteByte((byte)length);
                    }
                }
                WriteByte((byte)(0x80 + (end - _pos)));
            }
        }
    }
}
