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
                uint v = (uint)value;
                WriteByte((byte)v);
                if ((v & 0xFFFFFF80) != 0 && (v & 0xFFFFFF80) != 0xFFFFFF80)
                    WriteByte((byte)(v >> 8));
                if ((v & 0xFFFF8000) != 0 && (v & 0xFFFF8000) != 0xFFFF8000)
                    WriteByte((byte)(v >> 16));
                if ((v & 0xFF800000) != 0 && (v & 0xFF800000) != 0xFF800000)
                    WriteByte((byte)(v >> 24));
            }
            WriteLength(end - _pos);
            WriteByte(0x02);
        }

        public void Integer(long value)
        {
            int end = _pos;
            unchecked
            {
                ulong v = (ulong)value;
                WriteByte((byte)v);
                if ((v & 0xFFFFFFFFFFFFFF80) != 0 && (v & 0xFFFFFFFFFFFFFF80) != 0xFFFFFFFFFFFFFF80)
                    WriteByte((byte)(v >> 8));
                if ((v & 0xFFFFFFFFFFFF8000) != 0 && (v & 0xFFFFFFFFFFFF8000) != 0xFFFFFFFFFFFF8000)
                    WriteByte((byte)(v >> 16));
                if ((v & 0xFFFFFFFFFF800000) != 0 && (v & 0xFFFFFFFFFF800000) != 0xFFFFFFFFFF800000)
                    WriteByte((byte)(v >> 24));
                if ((v & 0xFFFFFFFF80000000) != 0 && (v & 0xFFFFFFFF80000000) != 0xFFFFFFFF80000000)
                    WriteByte((byte)(v >> 32));
                if ((v & 0xFFFFFF8000000000) != 0 && (v & 0xFFFFFF8000000000) != 0xFFFFFF8000000000)
                    WriteByte((byte)(v >> 40));
                if ((v & 0xFFFF800000000000) != 0 && (v & 0xFFFF800000000000) != 0xFFFF800000000000)
                    WriteByte((byte)(v >> 48));
                if ((v & 0xFF80000000000000) != 0 && (v & 0xFF80000000000000) != 0xFF80000000000000)
                    WriteByte((byte)(v >> 56));
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
                    if ((length & 0xFFFFFF00U) != 0)
                        WriteByte((byte)(length >> 8));
                    if ((length & 0xFFFF0000U) != 0)
                        WriteByte((byte)(length >> 16));
                    if ((length & 0xFF000000U) != 0)
                        WriteByte((byte)(length >> 24));
                }
                WriteByte((byte)(0x80 + (end - _pos)));
            }
        }
    }
}
