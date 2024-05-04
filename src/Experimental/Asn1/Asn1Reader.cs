using System;
using System.Runtime.CompilerServices;
using NSec.Cryptography;

namespace NSec.Experimental.Asn1
{
    // ITU-T X.690 5.0 DER
    internal ref struct Asn1Reader
    {
        internal const int MaxDepth = 7;

        private InlineRangeArray _stack;
        private readonly ReadOnlySpan<byte> _buffer;
        private int _depth;
        private bool _failed;

        public Asn1Reader(
            ReadOnlySpan<byte> buffer)
        {
            _stack = new InlineRangeArray();
            _stack[0] = Range.All;

            _buffer = buffer;
            _depth = 0;
            _failed = false;
        }

        public readonly bool Success => !_failed;

        public readonly bool SuccessComplete => !_failed && _depth == 0 && _buffer[_stack[0]].IsEmpty;

        public void BeginSequence()
        {
            Range range = Read(0x30);

            if (_failed)
            {
                Fail();
            }
            else
            {
                _depth++;
                if (_depth == MaxDepth)
                {
                    throw Error.InvalidOperation_InternalError(); // overflow
                }
                _stack[_depth] = range;
            }
        }

        public ReadOnlySpan<byte> BitString()
        {
            ReadOnlySpan<byte> bytes = _buffer[Read(0x03)];
            ReadOnlySpan<byte> value = default;

            if (_failed || bytes.IsEmpty || bytes[0] != 0)
            {
                Fail();
            }
            else
            {
                value = bytes[1..];
            }

            return value;
        }

        public bool Bool()
        {
            ReadOnlySpan<byte> bytes = _buffer[Read(0x01)];
            bool value = default;

            if (_failed || bytes.Length != 1 || (bytes[0] != 0x00 && bytes[0] != 0xFF))
            {
                Fail();
            }
            else
            {
                value = (bytes[0] != 0x00);
            }

            return value;
        }

        public void End()
        {
            if (_failed || !_buffer[_stack[_depth]].IsEmpty)
            {
                Fail();
            }
            else
            {
                if (_depth == 0)
                {
                    throw Error.InvalidOperation_InternalError(); // underflow
                }
                _depth--;
            }
        }

        public int Integer32()
        {
            ReadOnlySpan<byte> bytes = _buffer[Read(0x02)];
            int value = default;

            if (_failed || IsInvalidInteger(bytes, sizeof(int)))
            {
                Fail();
            }
            else
            {
                value = -(bytes[0] >> 7);
                for (int i = 0; i < bytes.Length; i++)
                {
                    value = (value << 8) | bytes[i];
                }
            }

            return value;
        }

        public long Integer64()
        {
            ReadOnlySpan<byte> bytes = _buffer[Read(0x02)];
            long value = default;

            if (_failed || IsInvalidInteger(bytes, sizeof(long)))
            {
                Fail();
            }
            else
            {
                value = -(bytes[0] >> 7);
                for (int i = 0; i < bytes.Length; i++)
                {
                    value = (value << 8) | bytes[i];
                }
            }

            return value;
        }

        public void Null()
        {
            ReadOnlySpan<byte> bytes = _buffer[Read(0x05)];

            if (_failed || !bytes.IsEmpty)
            {
                Fail();
            }
        }

        public ReadOnlySpan<byte> ObjectIdentifier()
        {
            return _buffer[Read(0x06)];
        }

        public ReadOnlySpan<byte> OctetString()
        {
            return _buffer[Read(0x04)];
        }

        private void Fail()
        {
            _failed = true;
            _depth = 0;
            _stack = default;
        }

        private readonly bool IsInvalidInteger(
            ReadOnlySpan<byte> bytes,
            int maxSize)
        {
            return bytes.Length == 0
                || bytes.Length > maxSize
                || bytes.Length > 1 && bytes[0] == 0x00 && (bytes[1] & 0x80) == 0x00
                || bytes.Length > 1 && bytes[0] == 0xFF && (bytes[1] & 0x80) == 0x80;
        }

        private Range Read(
            int tag)
        {
            Range range = _stack[_depth];
            ReadOnlySpan<byte> bytes = _buffer[range];

            if (_failed || bytes.Length < 2 || bytes[0] != tag)
            {
                goto failed;
            }

            int offset = 2;
            int length = 0;

            if ((bytes[1] & ~0x7F) == 0)
            {
                length = bytes[1];
            }
            else
            {
                int count = bytes[1] & 0x7F;
                if (count < 1 || count > sizeof(int) || count > bytes.Length - 2 || bytes[2] == 0)
                {
                    goto failed;
                }
                while (count-- > 0)
                {
                    length = (length << 8) | bytes[offset++];
                }
                if (length < 0x80)
                {
                    goto failed;
                }
            }

            if (length > bytes.Length - offset)
            {
                goto failed;
            }

            (int Offset, int Length) = range.GetOffsetAndLength(_buffer.Length);
            _stack[_depth] = new Range(Offset + offset + length, Offset + Length);
            return new Range(Offset + offset, Offset + offset + length);
        failed:
            Fail();
            return default;
        }

        [InlineArray(MaxDepth)]
        private struct InlineRangeArray
        {
            private Range _element0;
        }
    }
}
