using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Remoting;
using System.Text;
using System.Threading;
using EasyHook;
using System.Windows.Forms;

namespace MarvelSnapVariantReplacer
{
    internal class Inject
    {
        
        [STAThread]
        public static void Main()
        {
            string path = Directory.GetCurrentDirectory() + "\\MarvelSnapVariantHook.dll";

            while (true)
            {
                try
                {
                    RemoteHooking.Inject(Process.GetProcessesByName("SNAP")[0].Id, InjectionOptions.DoNotRequireStrongName, path, path, Directory.GetCurrentDirectory());
                }
                catch (Exception ex)
                {
                    //Console.WriteLine(ex.Message);
                    Thread.Sleep(1000);
                    continue;
                }
                break;
            }

            Application.Run();
        }
    }
}
