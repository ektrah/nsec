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
    internal struct Asn1Reader
    {
        private const int StackSize = 8;

#if UNSAFE
        private void* _buffer;
#else
        private ReadOnlySpan<byte> _buffer;
#endif
        private int _depth;
        private bool _failed;
        private StartAndLength[] _stack;

        public Asn1Reader(ref ReadOnlySpan<byte> buffer)
        {
#if UNSAFE
            _buffer = Unsafe.AsPointer(ref buffer);
#else
            _buffer = buffer;
#endif
            _depth = 0;
            _failed = false;
            _stack = new StartAndLength[StackSize];
            Top = new StartAndLength(0, buffer.Length);
        }

        public bool Success => !_failed;

        private ref StartAndLength Top => ref _stack[_depth];

        public void BeginSequence()
        {
            Debug.Assert(_depth + 1 != StackSize);
            StartAndLength bytes = Read(0x30);
            if (!_failed)
            {
                _depth++;
                Top = bytes;
            }
        }

        public void End()
        {
            if (_failed || !Top.IsEmpty)
            {
                Fail();
            }
            else
            {
                Debug.Assert(_depth != 0);
                _depth--;
            }
        }

        public int Integer32()
        {
            ReadOnlySpan<byte> bytes = Read(0x02).ApplyTo(_buffer);
            int value = 0;

            if (_failed || bytes.Length > sizeof(int))
            {
                Fail();
            }
            else if (bytes.Length != 0)
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

            if (_failed || bytes.Length > sizeof(long))
            {
                Fail();
            }
            else if (bytes.Length != 0)
            {
                value = -(bytes[0] >> 7);
                for (int i = 0; i < bytes.Length; i++)
                {
                    value = (value << 8) | bytes[i];
                }
            }

            return value;
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

        private StartAndLength Read(int tag)
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
                if (c > sizeof(int) || c > span.Length - 2)
                    goto fail;
                while (c-- > 0)
                    length = (length << 8) | span[pos++];
            }

            if (length < 0 || length > span.Length - pos)
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
