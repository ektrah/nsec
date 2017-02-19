//#define UNSAFE

using System;
#if UNSAFE
using System.Runtime.CompilerServices;
#endif

namespace NSec.Cryptography.Formatting
{
    // ITU-T X.690 5.0 DER
#if UNSAFE
    unsafe 
#endif
    internal struct Asn1Reader
    {
#if UNSAFE
        private void* _buffer;
#else
        private ReadOnlySpan<byte> _buffer;
#endif
        private int _depth;
        private bool _failed;
        private StartAndLength[] _stack;

        public Asn1Reader(
            ref ReadOnlySpan<byte> buffer, 
            int maxDepth = 8)
        {
#if UNSAFE
            _buffer = Unsafe.AsPointer(ref buffer);
#else
            _buffer = buffer;
#endif
            _depth = 0;
            _failed = false;
            _stack = new StartAndLength[maxDepth];
            Top = new StartAndLength(0, buffer.Length);
        }

        public bool Success => !_failed;

        public bool SuccessComplete => !_failed && _depth == 0 && Top.IsEmpty;

        private ref StartAndLength Top => ref _stack[_depth];

        public void BeginSequence()
        {
            StartAndLength bytes = Read(0x30);
            if (!_failed)
            {
                _depth++;
                Top = bytes;
            }
        }

        public ReadOnlySpan<byte> BitString()
        {
            ReadOnlySpan<byte> bytes = Read(0x03).ApplyTo(_buffer);
            ReadOnlySpan<byte> value = ReadOnlySpan<byte>.Empty;

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
            bool value = false;

            if (_failed || bytes.Length != 1 || bytes[0] != 0x00 && bytes[0] != 0xFF)
            {
                Fail();
            }
            else if (bytes[0] == 0xFF)
            {
                value = true;
            }

            return value;
        }

        public void End()
        {
            if (_failed || !Top.IsEmpty)
            {
                Fail();
            }
            else if (_depth == 0)
            {
                throw new IndexOutOfRangeException();
            }
            else
            {
                _depth--;
            }
        }

        public int Integer32()
        {
            ReadOnlySpan<byte> bytes = Read(0x02).ApplyTo(_buffer);
            int value = 0;

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
            long value = 0;

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

            if (_failed || bytes.Length != 0)
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
            Top = default(StartAndLength);
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
            StartAndLength top = Top;
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
            Top = top.Slice(pos + length);
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
#if UNSAFE
            public ReadOnlySpan<byte> ApplyTo(void* buffer) => Unsafe.AsRef<ReadOnlySpan<byte>>(buffer).Slice(_start, _length);
#else
            public ReadOnlySpan<byte> ApplyTo(ReadOnlySpan<byte> buffer) { return buffer.Slice(_start, _length); }
#endif
            public StartAndLength Slice(int start) { return new StartAndLength(_start + start, _length - start); }
            public StartAndLength Slice(int start, int length) { return new StartAndLength(_start + start, length); }
        }
    }
}
