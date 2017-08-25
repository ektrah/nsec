using System;
using System.Runtime.CompilerServices;

namespace NSec.Cryptography.Formatting
{
    // ITU-T X.690 5.0 DER
    internal struct Asn1Reader
    {
        internal const int MaxDepth = 7;

#pragma warning disable 0414
        private ReadOnlySpan<byte> _stack0;
        private ReadOnlySpan<byte> _stack1;
        private ReadOnlySpan<byte> _stack2;
        private ReadOnlySpan<byte> _stack3;
        private ReadOnlySpan<byte> _stack4;
        private ReadOnlySpan<byte> _stack5;
        private ReadOnlySpan<byte> _stack6;
#pragma warning restore 0414

        private int _depth;
        private bool _failed;

        public Asn1Reader(
            ReadOnlySpan<byte> buffer)
        {
            _stack0 = buffer;
            _stack1 = default;
            _stack2 = default;
            _stack3 = default;
            _stack4 = default;
            _stack5 = default;
            _stack6 = default;

            _depth = 0;
            _failed = false;
        }

        public bool Success => !_failed;

        public bool SuccessComplete => !_failed && _depth == 0 && _stack0.IsEmpty;

        public void BeginSequence()
        {
            if (!TryRead(0x30, out ReadOnlySpan<byte> bytes))
            {
                Fail();
            }
            else
            {
                _depth++;
                if (_depth == MaxDepth)
                {
                    throw new IndexOutOfRangeException();
                }
                Unsafe.Add(ref _stack0, _depth) = bytes;
            }
        }

        public ReadOnlySpan<byte> BitString()
        {
            ReadOnlySpan<byte> value = default;

            if (!TryRead(0x03, out ReadOnlySpan<byte> bytes) || bytes.Length == 0 || bytes[0] != 0)
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
            bool value = default;

            if (!TryRead(0x01, out ReadOnlySpan<byte> bytes) || bytes.Length != 1 || (bytes[0] != 0x00 && bytes[0] != 0xFF))
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
                    throw new IndexOutOfRangeException();
                }
                _depth--;
            }
        }

        public int Integer32()
        {
            int value = default;

            if (!TryRead(0x02, out ReadOnlySpan<byte> bytes) || IsInvalidInteger(bytes, sizeof(int)))
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
            long value = default;

            if (!TryRead(0x02, out ReadOnlySpan<byte> bytes) || IsInvalidInteger(bytes, sizeof(long)))
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
            if (!TryRead(0x05, out ReadOnlySpan<byte> bytes) || !bytes.IsEmpty)
            {
                Fail();
            }
        }

        public ReadOnlySpan<byte> ObjectIdentifier()
        {
            if (!TryRead(0x06, out ReadOnlySpan<byte> bytes))
            {
                Fail();
            }

            return bytes;
        }

        public ReadOnlySpan<byte> OctetString()
        {
            if (!TryRead(0x04, out ReadOnlySpan<byte> bytes))
            {
                Fail();
            }

            return bytes;
        }

        private void Fail()
        {
            _failed = true;
            _depth = 0;
            _stack0 = default;
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

        private bool TryRead(
            int tag,
            out ReadOnlySpan<byte> result)
        {
            ReadOnlySpan<byte> span = Unsafe.Add(ref _stack0, _depth);

            if (_failed || span.Length < 2 || span[0] != tag)
            {
                return false;
            }

            int start = 2;
            int length = 0;

            if ((span[1] & ~0x7F) == 0)
            {
                length = span[1];
            }
            else
            {
                int count = span[1] & 0x7F;
                if (count < 1 || count > sizeof(int) || count > span.Length - 2 || span[2] == 0)
                {
                    return false;
                }
                while (count-- > 0)
                {
                    length = (length << 8) | span[start++];
                }
                if (length < 0x80)
                {
                    return false;
                }
            }

            if (length > span.Length - start)
            {
                return false;
            }

            Unsafe.Add(ref _stack0, _depth) = span.Slice(start + length);
            result = span.Slice(start, length);
            return true;
        }
    }
}
