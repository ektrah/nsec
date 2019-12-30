using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using NSec.Cryptography;

namespace NSec.Experimental.Asn1
{
    // ITU-T X.690 5.0 DER
    internal ref struct Asn1Reader
    {
        internal const int MaxDepth = 7;

#pragma warning disable 0414
        private Span _stack0;
        private Span _stack1;
        private Span _stack2;
        private Span _stack3;
        private Span _stack4;
        private Span _stack5;
        private Span _stack6;
#pragma warning restore 0414

        private ReadOnlySpan<byte> _buffer;
        private int _depth;
        private bool _failed;

        public Asn1Reader(
            ReadOnlySpan<byte> buffer)
        {
            _stack0 = new Span(buffer);
            _stack1 = default;
            _stack2 = default;
            _stack3 = default;
            _stack4 = default;
            _stack5 = default;
            _stack6 = default;

            _buffer = buffer;
            _depth = 0;
            _failed = false;
        }

        public readonly bool Success => !_failed;

        public readonly bool SuccessComplete => !_failed && _depth == 0 && _stack0.IsEmpty;

        public void BeginSequence()
        {
            Span span = Read(0x30);

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
                Unsafe.Add(ref _stack0, _depth) = span;
            }
        }

        public ReadOnlySpan<byte> BitString()
        {
            ReadOnlySpan<byte> bytes = Read(0x03).ApplyTo(_buffer);
            ReadOnlySpan<byte> value = default;

            if (_failed || bytes.IsEmpty || bytes[0] != 0)
            {
                Fail();
            }
            else
            {
                value = bytes.Slice(1);
            }

            return value;
        }

        public bool Bool()
        {
            ReadOnlySpan<byte> bytes = Read(0x01).ApplyTo(_buffer);
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
            if (_failed || !Unsafe.Add(ref _stack0, _depth).IsEmpty)
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
            ReadOnlySpan<byte> bytes = Read(0x02).ApplyTo(_buffer);
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
            ReadOnlySpan<byte> bytes = Read(0x02).ApplyTo(_buffer);
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
            Span span = Read(0x05);

            if (_failed || !span.IsEmpty)
            {
                Fail();
            }
        }

        public ReadOnlySpan<byte> ObjectIdentifier()
        {
            return Read(0x06).ApplyTo(_buffer);
        }

        public ReadOnlySpan<byte> OctetString()
        {
            return Read(0x04).ApplyTo(_buffer);
        }

        private void Fail()
        {
            _failed = true;
            _depth = 0;
            _stack0 = default;
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

        private Span Read(
            int tag)
        {
            Span span = Unsafe.Add(ref _stack0, _depth);
            ReadOnlySpan<byte> bytes = span.ApplyTo(_buffer);

            if (_failed || bytes.Length < 2 || bytes[0] != tag)
            {
                goto failed;
            }

            int start = 2;
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
                    length = (length << 8) | bytes[start++];
                }
                if (length < 0x80)
                {
                    goto failed;
                }
            }

            if (length > bytes.Length - start)
            {
                goto failed;
            }

            Unsafe.Add(ref _stack0, _depth) = span.Slice(start + length);
            return span.Slice(start, length);
        failed:
            Fail();
            return default;
        }

        private readonly struct Span
        {
            private readonly int _start;
            private readonly int _length;

            public Span(ReadOnlySpan<byte> buffer)
                : this(0, buffer.Length)
            {
            }

            private Span(int start, int length)
            {
                _start = start;
                _length = length;
            }

            public bool IsEmpty => _length == 0;

            public int Length => _length;

            public int Start => _start;

            public ReadOnlySpan<byte> ApplyTo(ReadOnlySpan<byte> buffer)
            {
                return buffer.Slice(_start, _length);
            }

            public Span Slice(int start)
            {
                Debug.Assert(start >= 0 && start <= _length);

                return new Span(_start + start, _length - start);
            }

            public Span Slice(int start, int length)
            {
                Debug.Assert(start >= 0 && start <= _length);
                Debug.Assert(length >= 0 && length <= _length - start);

                return new Span(_start + start, length);
            }
        }
    }
}
