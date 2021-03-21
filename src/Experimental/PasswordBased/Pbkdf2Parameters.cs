using System.Runtime.InteropServices;

namespace NSec.Experimental.PasswordBased
{
    [StructLayout(LayoutKind.Auto)]
    public ref struct Pbkdf2Parameters
    {
        public int IterationCount;
    }
}
