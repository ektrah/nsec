using System.Runtime.InteropServices;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Auto)]
    public struct ScryptParameters
    {
        public long Cost;
        public int BlockSize;
        public int Parallelization;
    }
}
