using NSec.Cryptography;
using Xunit;

namespace NSec.tests.Algorithms
{
    public class ChaCha20Tests
    {
        [Fact]
        public static void Properties()
        {
            var a = StreamCipherAlgorithm.ChaCha20;
            Assert.Equal(32, a.KeySize);
            Assert.Equal(12, a.NonceSize);
        }
    }
}
