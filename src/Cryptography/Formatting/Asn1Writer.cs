//#define UNSAFE

using System;
using System.Diagnostics;
#if UNSAFE
using System.Runtime.CompilerServices;
#endif

namespace NSec.Cryptography.Formatting
{
#if UNSAFE
    unsafe 
#endif
    internal struct Asn1Writer
    {
        private const int StackSize = 8;

#if UNSAFE
        private void* _bytes;
#else
        private Span<byte> _bytes;
#endif
        private int _depth;
        private int _pos;
        private int[] _stack;

        public Asn1Writer(ref Span<byte> bytes)
        {
#if UNSAFE
            _bytes = Unsafe.AsPointer(ref bytes);
#else
            _bytes = bytes;
#endif
            _depth = 0;
            _pos = bytes.Length;
            _stack = new int[StackSize];
        }

#if UNSAFE
        public ReadOnlySpan<byte> Bytes => Unsafe.AsRef<Span<byte>>(_bytes).Slice(_pos);
#else
        public ReadOnlySpan<byte> Bytes => _bytes.Slice(_pos);
#endif

        public void BeginSequence()
        {
            Debug.Assert(_depth != 0);
            _depth--;
            WriteLength(_stack[_depth] - _pos);
            WriteByte(0x30);
        }

        public void End()
        {
            Debug.Assert(_depth != StackSize);
            _stack[_depth] = _pos;
            _depth++;
        }

        public void Integer(int value)
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

        public void Integer(long value)
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

        public void ObjectIdentifier(ReadOnlySpan<byte> oid)
        {
            WriteBytes(oid);
            WriteLength(oid.Length);
            WriteByte(0x06);
        }

        public void OctetString(ReadOnlySpan<byte> octets)
        {
            WriteBytes(octets);
            WriteLength(octets.Length);
            WriteByte(0x04);
        }

        private void WriteByte(byte value)
        {
            if (_pos == 0)
                throw new ArgumentException();

            _pos--;
#if UNSAFE
            Unsafe.AsRef<Span<byte>>(_bytes)[_pos] = value;
#else
            _bytes[_pos] = value;
#endif
        }

        private void WriteBytes(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length > _pos)
                throw new ArgumentException();

            _pos -= bytes.Length;
#if UNSAFE
            bytes.CopyTo(Unsafe.AsRef<Span<byte>>(_bytes).Slice(_pos));
#else
            bytes.CopyTo(_bytes.Slice(_pos));
#endif
        }

        private void WriteLength(int length)
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
