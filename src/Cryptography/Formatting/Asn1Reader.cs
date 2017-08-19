using System;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography.Formatting
{
    // ITU-T X.690 5.0 DER
    internal struct Asn1Reader
    {
        private readonly ReadOnlySpan<byte> _buffer;
        private readonly int _maxDepth;

        private int _depth;
        private bool _failed;

#pragma warning disable 0414
        private StartAndLength _stack0;
        private StartAndLength _stack1;
        private StartAndLength _stack2;
        private StartAndLength _stack3;
        private StartAndLength _stack4;
        private StartAndLength _stack5;
        private StartAndLength _stack6;
        private StartAndLength _stack7;
        private StartAndLength _stack8;
#pragma warning restore 0414

        public Asn1Reader(
            ReadOnlySpan<byte> buffer,
            int maxDepth = 8)
        {
            if (maxDepth < 0 || maxDepth > 8)
                throw new IndexOutOfRangeException();

            _buffer = buffer;
            _maxDepth = 1 + maxDepth;

            _depth = 0;
            _failed = false;

            _stack0 = new StartAndLength(0, buffer.Length);
            _stack1 = default(StartAndLength);
            _stack2 = default(StartAndLength);
            _stack3 = default(StartAndLength);
            _stack4 = default(StartAndLength);
            _stack5 = default(StartAndLength);
            _stack6 = default(StartAndLength);
            _stack7 = default(StartAndLength);
            _stack8 = default(StartAndLength);
        }

        public bool Success => !_failed;

        public bool SuccessComplete => !_failed && _depth == 0 && _stack0.IsEmpty;

        public void BeginSequence()
        {
            StartAndLength bytes = Read(0x30);

            if (_failed)
            {
                Fail();
            }
            else
            {
                _depth++;
                if (_depth == _maxDepth)
                    throw new IndexOutOfRangeException();
                Unsafe.Add(ref _stack0, _depth) = bytes;
            }
        }

        public ReadOnlySpan<byte> BitString()
        {
            ReadOnlySpan<byte> bytes = Read(0x03).ApplyTo(_buffer);
            ReadOnlySpan<byte> value = default(ReadOnlySpan<byte>);

            if (_failed || bytes.Length == 0 || bytes[0] != 0)
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
            bool value = default(bool);

            if (_failed || bytes.Length != 1 || (bytes[0] != 0x00 && bytes[0] != 0xFF))
            {
                Fail();
            }
            else
            {
                value = (bytes[0] == 0xFF);
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
                    throw new IndexOutOfRangeException();
                _depth--;
            }
        }

        public int Integer32()
        {
            ReadOnlySpan<byte> bytes = Read(0x02).ApplyTo(_buffer);
            int value = default(int);

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
            long value = default(long);

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
            StartAndLength bytes = Read(0x05);

            if (_failed || !bytes.IsEmpty)
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
            _stack0 = default(StartAndLength);
        }

        private bool IsInvalidInteger(
            ReadOnlySpan<byte> bytes,
            int maxSize)
        {
            return bytes.Length == 0
                || bytes.Length > maxSize
                || bytes.Length > 1 && bytes[0] == 0x00 && (bytes[1] & 0x80) == 0x00
                || bytes.Length > 1 && bytes[0] == 0xFF && (bytes[1] & 0x80) == 0x80;
        }

        private StartAndLength Read(
            int tag)
        {
            StartAndLength top = Unsafe.Add(ref _stack0, _depth);
            StartAndLength result = default(StartAndLength);
            ReadOnlySpan<byte> span = top.ApplyTo(_buffer);
            int length = 0;

            if (_failed || span.Length < 2 || span[0] != tag)
                goto fail;

            int pos = 2;
            if ((span[1] & 0x80) == 0)
            {
                length = span[1];
            }
            else
            {
                int c = span[1] & 0x7F;
                if (c == 0 || c > sizeof(int) || c > span.Length - 2 || span[2] == 0)
                    goto fail;
                while (c-- > 0)
                    length = (length << 8) | span[pos++];
                if (length < 0x80)
                    goto fail;
            }

            if (length > span.Length - pos)
                goto fail;

            result = top.Slice(pos, length);
            Unsafe.Add(ref _stack0, _depth) = top.Slice(pos + length);
            goto done;
        fail:
            Fail();
        done:
            return result;
        }

        private struct StartAndLength
        {
            private int _start;
            private int _length;
            public StartAndLength(int start, int length) { _start = start; _length = length; }
            public bool IsEmpty => _length == 0;
            public int Length => _length;
            public int Start => _start;
            public ReadOnlySpan<byte> ApplyTo(ReadOnlySpan<byte> buffer) { return buffer.Slice(_start, _length); }
            public StartAndLength Slice(int start) { return new StartAndLength(_start + start, _length - start); }
            public StartAndLength Slice(int start, int length) { return new StartAndLength(_start + start, length); }
        }
    }
}
