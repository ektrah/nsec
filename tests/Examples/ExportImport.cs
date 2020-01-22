using System;
using NSec.Cryptography;
using System.Collections.Generic;
using Xunit;

namespace NSec.Tests.Examples
{
    public static class ExportImport
    {
        [Fact]
        public static void ExportImportNSecPrivateKey()
        {
            // mock System.IO.File
            var File = new Dictionary<string, byte[]>();

            {
                #region ExportImport: Export

                var algorithm = SignatureAlgorithm.Ed25519;

                var creationParameters = new KeyCreationParameters
                {
                    ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving
                };

                // create a new key
                using var key = new Key(algorithm, creationParameters);

                // export it
                var blob = key.Export(KeyBlobFormat.NSecPrivateKey);

                File.WriteAllBytes("myprivatekey.nsec", blob);

                #endregion
            }

            {
                #region ExportImport: Import

                var algorithm = SignatureAlgorithm.Ed25519;

                var blob = File.ReadAllBytes("myprivatekey.nsec");

                // re-import it
                using var key = Key.Import(algorithm, blob, KeyBlobFormat.NSecPrivateKey);

                var signature = algorithm.Sign(key, /*{*/new byte[0]/*}*/);

                #endregion
            }
        }

        private static void WriteAllBytes(this Dictionary<string, byte[]> dictionary, string key, byte[] value)
        {
            dictionary[key] = value;
        }

        private static byte[] ReadAllBytes(this Dictionary<string, byte[]> dictionary, string key)
        {
            return dictionary[key];
        }
    }
}
