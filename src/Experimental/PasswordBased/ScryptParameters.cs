using System.Runtime.InteropServices;

namespace NSec.Experimental.PasswordBased
{
    [StructLayout(LayoutKind.Auto)]
    public ref struct ScryptParameters
    {
        public long Cost;
        public int BlockSize;
        public int Parallelization;
    }
}
