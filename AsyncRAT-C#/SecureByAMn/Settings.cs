using System.IO;
using System.Runtime.InteropServices;

namespace SecureByAMn
{
    public static class Settings
    {
        public static string code = @"#AES_256_GCM_ENCRYPTION#";
        public static string passwd = @"#PASSWOR_AES_256_GCM#";
        public static string processRunpe = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "#ProcessRunPE#");
    }
}