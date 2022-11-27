using System;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    [DebuggerDisplay("Size = {Size}")]
    public sealed class SharedSecret : IDisposable
    {
        private const uint NSecBlobHeader = 0xDE7000DE;
        private const int MaxSize = 128;

        private readonly KeyExportPolicies _exportPolicy;
        private readonly SecureMemoryHandle _handle;

        private bool _exported;

        internal SharedSecret(
            in SharedSecretCreationParameters creationParameters,
            SecureMemoryHandle sharedSecretHandle)
        {
            _exportPolicy = creationParameters.ExportPolicy;
            _handle = sharedSecretHandle;
        }

        public KeyExportPolicies ExportPolicy => _exportPolicy;

        public int Size => _handle.Size;

        internal SecureMemoryHandle Handle => _handle;

        public static SharedSecret Import(
            ReadOnlySpan<byte> blob,
            SharedSecretBlobFormat format,
            in SharedSecretCreationParameters creationParameters = default)
        {
            Sodium.Initialize();

            SecureMemoryHandle? sharedSecretHandle = default;
            bool success = false;

            try
            {
                success = TryImportCore(blob, format, out sharedSecretHandle);
            }
            finally
            {
                if (!success && sharedSecretHandle != null)
                {
                    sharedSecretHandle.Dispose();
                }
            }

            if (!success || sharedSecretHandle == null)
            {
                throw Error.Format_InvalidBlob();
            }

            return new SharedSecret(in creationParameters, sharedSecretHandle);
        }

        public static bool TryImport(
            ReadOnlySpan<byte> blob,
            SharedSecretBlobFormat format,
            out SharedSecret? result,
            in SharedSecretCreationParameters creationParameters = default)
        {
            Sodium.Initialize();

            SecureMemoryHandle? sharedSecretHandle = default;
            bool success = false;

            try
            {
                success = TryImportCore(blob, format, out sharedSecretHandle);
            }
            finally
            {
                if (!success && sharedSecretHandle != null)
                {
                    sharedSecretHandle.Dispose();
                }
            }

            result = success && sharedSecretHandle != null ? new SharedSecret(in creationParameters, sharedSecretHandle) : null;
            return success;
        }

        public void Dispose()
        {
            _handle.Dispose();
        }

        public byte[] Export(
            SharedSecretBlobFormat format)
        {
            if (_handle.IsClosed)
            {
                throw new ObjectDisposedException(typeof(SharedSecret).FullName);
            }

            if ((_exportPolicy & KeyExportPolicies.AllowPlaintextExport) == 0)
            {
                if ((_exportPolicy & KeyExportPolicies.AllowPlaintextArchiving) == 0)
                {
                    throw Error.InvalidOperation_ExportNotAllowed();
                }
                if (_exported)
                {
                    throw Error.InvalidOperation_AlreadyArchived();
                }
            }

            TryExportCore(_handle, format, Span<byte>.Empty, out int blobSize);
            byte[] blob = new byte[blobSize];

            if (!TryExportCore(_handle, format, blob, out blobSize))
            {
                throw Error.InvalidOperation_InternalError();
            }

            Debug.Assert(blobSize == blob.Length);
            _exported = true;
            return blob;
        }

        public int GetExportBlobSize(
            SharedSecretBlobFormat format)
        {
            if (_handle.IsClosed)
            {
                throw new ObjectDisposedException(typeof(SharedSecret).FullName);
            }

            TryExportCore(_handle, format, Span<byte>.Empty, out int blobSize);
            return blobSize;
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string? ToString()
        {
            return typeof(SharedSecret).ToString();
        }

        public bool TryExport(
            SharedSecretBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            if (_handle.IsClosed)
            {
                throw new ObjectDisposedException(typeof(SharedSecret).FullName);
            }

            if ((_exportPolicy & KeyExportPolicies.AllowPlaintextExport) == 0)
            {
                if ((_exportPolicy & KeyExportPolicies.AllowPlaintextArchiving) == 0)
                {
                    throw Error.InvalidOperation_ExportNotAllowed();
                }
                if (_exported)
                {
                    throw Error.InvalidOperation_AlreadyArchived();
                }
            }

            if (!TryExportCore(_handle, format, blob, out blobSize))
            {
                return false;
            }

            _exported = true;
            return true;
        }

        private static bool TryExportCore(
            SecureMemoryHandle sharedSecretHandle,
            SharedSecretBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            return format switch
            {
                SharedSecretBlobFormat.RawSharedSecret => TryExportRaw(sharedSecretHandle, blob, out blobSize),
                SharedSecretBlobFormat.NSecSharedSecret => TryExportNSec(sharedSecretHandle, blob, out blobSize),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        private static bool TryExportNSec(
            SecureMemoryHandle sharedSecretHandle,
            Span<byte> blob,
            out int blobSize)
        {
            blobSize = sizeof(uint) + sizeof(short) + sizeof(short) + sharedSecretHandle.Size;

            if (blob.Length < blobSize)
            {
                return false;
            }

            BinaryPrimitives.WriteUInt32BigEndian(blob, NSecBlobHeader);
            BinaryPrimitives.WriteInt16LittleEndian(blob[sizeof(uint)..], (short)sharedSecretHandle.Size);
            BinaryPrimitives.WriteInt16LittleEndian(blob[(sizeof(uint) + sizeof(short))..], 0);
            sharedSecretHandle.CopyTo(blob[(sizeof(uint) + sizeof(short) + sizeof(short))..]);
            return true;
        }

        private static bool TryExportRaw(
            SecureMemoryHandle sharedSecretHandle,
            Span<byte> blob,
            out int blobSize)
        {
            blobSize = sharedSecretHandle.Size;

            if (blob.Length < blobSize)
            {
                return false;
            }

            sharedSecretHandle.CopyTo(blob);
            return true;
        }

        private static bool TryImportCore(
            ReadOnlySpan<byte> blob,
            SharedSecretBlobFormat format,
            out SecureMemoryHandle? sharedSecretHandle)
        {
            return format switch
            {
                SharedSecretBlobFormat.RawSharedSecret => TryImportRaw(blob, out sharedSecretHandle),
                SharedSecretBlobFormat.NSecSharedSecret => TryImportNSec(blob, out sharedSecretHandle),
                _ => throw Error.Argument_FormatNotSupported(nameof(format), format.ToString()),
            };
        }

        private static bool TryImportNSec(
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle? sharedSecretHandle)
        {
            if (blob.Length < sizeof(uint) + sizeof(short) + sizeof(short) ||
                blob.Length > sizeof(uint) + sizeof(short) + sizeof(short) + MaxSize ||
                BinaryPrimitives.ReadUInt32BigEndian(blob) != NSecBlobHeader ||
                BinaryPrimitives.ReadInt16LittleEndian(blob[sizeof(uint)..]) != blob.Length - (sizeof(uint) + sizeof(short) + sizeof(short)))
            {
                sharedSecretHandle = null;
                return false;
            }

            sharedSecretHandle = SecureMemoryHandle.CreateFrom(blob[(sizeof(uint) + sizeof(short) + sizeof(short))..]);
            return true;
        }

        private static bool TryImportRaw(
            ReadOnlySpan<byte> blob,
            out SecureMemoryHandle? sharedSecretHandle)
        {
            if (blob.Length > MaxSize)
            {
                sharedSecretHandle = null;
                return false;
            }

            sharedSecretHandle = SecureMemoryHandle.CreateFrom(blob);
            return true;
        }
    }
}
